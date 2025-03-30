#include <stdio.h>
#include <string.h>

#include <rawstor.h>

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qobject/qdict.h"
#include "qobject/qstring.h"
#include "qemu/cutils.h"
#include "qemu/module.h"
#include "qemu/option.h"
#include "block/block-io.h"
#include "block/block_int.h"


typedef struct {
    RawstorUUID object_id;
    RawstorObject *object;
} BDRVRawstorState;


static QemuOptsList runtime_opts = {
    .name = "null",
    .head = QTAILQ_HEAD_INITIALIZER(runtime_opts.head),
    .desc = {
        {
            .name = "object-id",
            .type = QEMU_OPT_STRING,
            .help = "rawstor object id",
        },
        { /* end of list */ }
    },
};


static const char *const qemu_rawstor_strong_runtime_opts[] = {
    "object-id",

    NULL
};


static int qemu_rawstor_open(BlockDriverState *bs, QDict *options, int flags,
                             Error **errp)
{
    QemuOpts *opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &error_abort);

    const char *object_id_string = qemu_opt_get(opts, "object-id");
    if (object_id_string == NULL) {
        error_setg(errp, "object-id option required");
        return -1;
    }
    RawstorUUID object_id;
    if (rawstor_uuid_from_string(&object_id, object_id_string)) {
        error_setg(errp, "object-id must be valid UUID");
        return -1;
    }

    RawstorObject *object;
    if (rawstor_object_open(&object_id, &object)) {
        error_setg(errp, "Failed to open rawstor object");
        return -1;
    }

    BDRVRawstorState *s = bs->opaque;
    s->object_id = object_id;
    s->object = object;

    qemu_opts_del(opts);

    return 0;
}


static void qemu_rawstor_close(BlockDriverState *bs) {
    BDRVRawstorState *s = bs->opaque;
    rawstor_object_close(s->object);
}


static void qemu_rawstor_parse_filename(const char *filename, QDict *options,
                                        Error **errp) {
    const char *start;

    if (!strstart(filename, "rawstor:", &start)) {
        error_setg(errp, "File name must start with 'rawstor:'");
        return;
    }

    char *buf = strdup(start);
    char *name = buf;

    while (true) {
        char *value = strchr(name, '=');
        if (!value) {
            error_setg(errp, "Equal sign expected near: %s", name);
            break;
        }
        *value = '\0';
        value += 1;

        char *next = strchr(value, ':');
        if (next) {
            *next = '\0';
        }

        qdict_put_str(options, name, value);

        if (next) {
            name = next + 1;
        } else {
            break;
        }
    }

    free(buf);
}


static int64_t coroutine_fn qemu_rawstor_getlength(BlockDriverState *bs) {
    BDRVRawstorState *s = bs->opaque;
    RawstorObjectSpec spec;
    if (rawstor_object_spec(&s->object_id, &spec)) {
        return -1;
    }
    return spec.size;
}


static int qemu_rawstor_completion(
    RawstorObject *object, size_t size, size_t res, int error, void *data)
{
    int *completed = (int*)data;
    /**
     * TODO: Handle partial request here.
     */
    *completed = 1;
    return 0;
}


static int
coroutine_fn qemu_rawstor_preadv(BlockDriverState *bs, int64_t offset,
                                 int64_t bytes, QEMUIOVector *qiov,
                                 BdrvRequestFlags flags) {
    BDRVRawstorState *s = bs->opaque;
    int completed = 0;

    /**
     * TODO: Do we have to assert(bytes == sum(qiov))?
     */
    if (rawstor_object_preadv(
        s->object,
        qiov->iov, qiov->niov, bytes, offset,
        qemu_rawstor_completion, &completed))
    {
        return -1;
    }

    while (!completed) {
        /**
         * TODO: Yep, we are still synchronious.
         */
        RawstorIOEvent *event = rawstor_wait_event();
        if (event == NULL) {
            return -1;
        }
        /*
        RawstorIOEvent *event = rawstor_wait_event_timeout(0);
        if (event == NULL) {
            qemu_coroutine_yield();
            continue;
        }
        */

        int rval = rawstor_dispatch_event(event);

        rawstor_release_event(event);

        if (rval < 0) {
            /**
             * TODO: What should we do here when event dispatcher
             * returns an error.
             */
            errno = -rval;
            perror("rawstor_dispatch_event() failed");
            return rval;
        }
    }

    return 0;
}


static int
coroutine_fn qemu_rawstor_pwritev(BlockDriverState *bs, int64_t offset,
                                  int64_t bytes, QEMUIOVector *qiov,
                                  BdrvRequestFlags flags) {
    BDRVRawstorState *s = bs->opaque;
    int completed = 0;

    /**
     * TODO: Do we have to assert(bytes == sum(qiov))?
     */
    if (rawstor_object_pwritev(
        s->object,
        qiov->iov, qiov->niov, bytes, offset,
        qemu_rawstor_completion, &completed))
    {
        return -1;
    }

    while (!completed) {
        /**
         * TODO: Yep, we are still synchronious.
         */
        RawstorIOEvent *event = rawstor_wait_event();
        if (event == NULL) {
            return -1;
        }
        /*
        RawstorIOEvent *event = rawstor_wait_event_timeout(0);
        if (event == NULL) {
            qemu_coroutine_yield();
            continue;
        }
        */

        int rval = rawstor_dispatch_event(event);

        rawstor_release_event(event);

        if (rval < 0) {
            /**
             * TODO: What should we do here when event dispatcher
             * returns an error?
             */
            errno = -rval;
            perror("rawstor_dispatch_event() failed");
            return rval;
        }
    }

    return 0;
}


static int
coroutine_fn qemu_rawstor_block_status(BlockDriverState *bs,
                                       bool want_zero, int64_t offset,
                                       int64_t bytes, int64_t *pnum,
                                       int64_t *map,
                                       BlockDriverState **file) {
    return BDRV_BLOCK_DATA | BDRV_BLOCK_OFFSET_VALID;
}


static BlockDriver bdrv_rawstor = {
    .format_name            = "rawstor",
    .protocol_name          = "rawstor",
    .instance_size          = sizeof(BDRVRawstorState),

    .bdrv_open              = qemu_rawstor_open,
    .bdrv_close             = qemu_rawstor_close,
    .bdrv_parse_filename    = qemu_rawstor_parse_filename,
    .bdrv_co_getlength      = qemu_rawstor_getlength,

    .bdrv_co_preadv         = qemu_rawstor_preadv,
    .bdrv_co_pwritev        = qemu_rawstor_pwritev,

    .bdrv_co_block_status   = qemu_rawstor_block_status,

    .strong_runtime_opts    = qemu_rawstor_strong_runtime_opts,
};


static void bdrv_rawstor_init(void) {
    if (rawstor_initialize(NULL)) {
        printf("Failed to initialize rawstor\n");
        /**
         * TODO: We have to return fatal error somewhere.
         */
        return;
    }
    bdrv_register(&bdrv_rawstor);
}

block_init(bdrv_rawstor_init);
