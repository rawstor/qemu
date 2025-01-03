#include <stdio.h>
#include <string.h>

#include <rawstor.h>

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qstring.h"
#include "qemu/cutils.h"
#include "qemu/module.h"
#include "qemu/option.h"
#include "block/block-io.h"
#include "block/block_int.h"


typedef struct {
    size_t size;
    RawstorDevice *device;
} BDRVRawstorState;


static QemuOptsList runtime_opts = {
    .name = "null",
    .head = QTAILQ_HEAD_INITIALIZER(runtime_opts.head),
    .desc = {
        {
            .name = BLOCK_OPT_SIZE,
            .type = QEMU_OPT_SIZE,
            .help = "size of the rawstor device",
        },
        { /* end of list */ }
    },
};


static const char *const qemu_rawstor_strong_runtime_opts[] = {
    BLOCK_OPT_SIZE,

    NULL
};


static int qemu_rawstor_open(BlockDriverState *bs, QDict *options, int flags,
                             Error **errp) {
    BDRVRawstorState *s = bs->opaque;

    QemuOpts *opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &error_abort);

    s->size = qemu_opt_get_size(opts, BLOCK_OPT_SIZE, 1 << 30);
    s->device = rawstor_alloc(s->size);

    qemu_opts_del(opts);
    return 0;
}


static void qemu_rawstor_close(BlockDriverState *bs) {
    BDRVRawstorState *s = bs->opaque;

    rawstor_free(s->device);
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
    return s->size;
}


static int
coroutine_fn qemu_rawstor_preadv(BlockDriverState *bs, int64_t offset,
                                 int64_t bytes, QEMUIOVector *qiov,
                                 BdrvRequestFlags flags) {
    BDRVRawstorState *s = bs->opaque;

    rawstor_readv(s->device, offset, bytes, qiov->iov, qiov->niov);

    return 0;
}


static int
coroutine_fn qemu_rawstor_pwritev(BlockDriverState *bs, int64_t offset,
                                  int64_t bytes, QEMUIOVector *qiov,
                                  BdrvRequestFlags flags) {
    BDRVRawstorState *s = bs->opaque;

    rawstor_writev(s->device, offset, bytes, qiov->iov, qiov->niov);

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
    bdrv_register(&bdrv_rawstor);
}

block_init(bdrv_rawstor_init);
