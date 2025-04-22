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
#include "qemu/thread.h"
#include "block/block-io.h"
#include "block/block_int.h"

#include <unistd.h>


#define RAWSTOR_EXIT_SUCCESS 1


typedef struct {
    RawstorUUID object_id;
    RawstorObject *object;
    int input_fd;
    int output_fd;
    QemuMutex mutex;
    QemuThread rawstor_thread;
} BDRVRawstorState;


typedef int (RawstorMethod)(
    RawstorObject *object,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data);


typedef struct RawstorTask {
    BDRVRawstorState *state;
    AioContext *ctx;
    Coroutine *co;

    int64_t offset;
    int64_t bytes;
    QEMUIOVector *qiov;
    RawstorMethod *method;

    bool completed;
} RawstorTask;


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


static int fd_add_flag(int fd, int flag) {
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1) {
        return -errno;
    }

    if (flags & flag) {
        return 0;
    }

    flags = flags | flag;
    if (fcntl(fd, F_SETFL, flags) == -1) {
        return -errno;
    }

    return 0;
}


static void qemu_rawstor_finish_bh(void *opaque) {
    RawstorTask *task = (RawstorTask*)opaque;
    task->completed = true;
    aio_co_wake(task->co);
}


static int rawstor_completion(
    RawstorObject *object, size_t size, size_t res, int error, void *opaque)
{
    RawstorTask *task = (RawstorTask*)opaque;

    aio_bh_schedule_oneshot(task->ctx, qemu_rawstor_finish_bh, task);

    return 0;
}


static int rawstor_task(RawstorIOEvent *event, void *opaque) {
    RawstorTask **taskptrptr = opaque;
    RawstorTask *taskptr = *taskptrptr;
    BDRVRawstorState *state = taskptr->state;

    if (rawstor_io_event_error(event) != 0) {
        errno = rawstor_io_event_error(event);
        return -errno;
    }

    if (rawstor_io_event_result(event) == 0) {
        return RAWSTOR_EXIT_SUCCESS;
    }

    if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
        errno = EIO;
        return -errno;
    }

    if (taskptr->method(
        state->object,
        taskptr->qiov->iov, taskptr->qiov->niov, taskptr->bytes, taskptr->offset,
        rawstor_completion, taskptr))
    {
        perror("rawstor_method() failed");
        return -1;
    }

    rawstor_fd_read(
        state->input_fd, taskptrptr, sizeof(*taskptrptr), rawstor_task, taskptrptr);
    return 0;
}


static void* rawstor_thread(void *opaque) {
    BDRVRawstorState *state = opaque;
    RawstorTask *taskptr;

    rawstor_fd_read(state->input_fd, &taskptr, sizeof(taskptr), rawstor_task, &taskptr);
    while (true) {
        RawstorIOEvent *event = rawstor_wait_event();
        if (event == NULL) {
            break;
        }

        int rval = rawstor_dispatch_event(event);

        rawstor_release_event(event);

        if (rval == RAWSTOR_EXIT_SUCCESS) {
            return NULL;
        }

        if (rval < 0) {
            /**
             * TODO: What should we do here when event dispatcher
             * returns an error?
             */
            errno = -rval;
            perror("rawstor_dispatch_event() failed");
        }
    }
    return NULL;
}


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

    int filedes[2];
    if (pipe(filedes)) {
        error_setg(errp, "Failed to create pipe");
        return -1;
    }

    if (fd_add_flag(filedes[0], O_NONBLOCK)) {
        error_setg(errp, "Failed to set O_NONBLOCK");
        return -1;
    }

    if (fd_add_flag(filedes[1], O_NONBLOCK)) {
        error_setg(errp, "Failed to set O_NONBLOCK");
        return -1;
    }

    RawstorObject *object;
    if (rawstor_object_open(&object_id, &object)) {
        error_setg(errp, "Failed to open rawstor object");
        return -1;
    }

    BDRVRawstorState *state = bs->opaque;
    state->object_id = object_id;
    state->object = object;
    state->input_fd = filedes[0];
    state->output_fd = filedes[1];
    
    qemu_mutex_init(&state->mutex);

    qemu_thread_create(
        &state->rawstor_thread,
        "block/rawstor/eventloop_thread", rawstor_thread, state,
        QEMU_THREAD_JOINABLE);

    qemu_opts_del(opts);

    return 0;
}


static void qemu_rawstor_close(BlockDriverState *bs) {
    BDRVRawstorState *state = bs->opaque;

    close(state->output_fd);
    qemu_thread_join(&state->rawstor_thread);
    close(state->input_fd);

    qemu_mutex_destroy(&state->mutex);

    rawstor_object_close(state->object);
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


static int
coroutine_fn qemu_rawstor_start_co(BlockDriverState *bs, int64_t offset,
                                   int64_t bytes, QEMUIOVector *qiov,
                                   BdrvRequestFlags flags,
                                   RawstorMethod *method)
{
    BDRVRawstorState *state = bs->opaque;
    RawstorTask task = {
        .state = state,
        .ctx = bdrv_get_aio_context(bs),
        .co = qemu_coroutine_self(),
        .offset = offset,
        .bytes = bytes,
        .qiov = qiov,
        .method = method,
        .completed = 0,
    };
    RawstorTask *taskptr = &task;

    qemu_mutex_lock(&state->mutex);

    int res = write(state->output_fd, &taskptr, sizeof(taskptr));
    if (res != sizeof(taskptr)) {
        perror("write() failed");
        qemu_mutex_unlock(&state->mutex);
        return -1;
    }

    qemu_mutex_unlock(&state->mutex);

    while (!task.completed) {
        qemu_coroutine_yield();
    }

    return 0;
}


static int
coroutine_fn qemu_rawstor_preadv(BlockDriverState *bs, int64_t offset,
                                 int64_t bytes, QEMUIOVector *qiov,
                                 BdrvRequestFlags flags)
{
    return qemu_rawstor_start_co(
        bs, offset, bytes, qiov, flags, rawstor_object_preadv);
}


static int
coroutine_fn qemu_rawstor_pwritev(BlockDriverState *bs, int64_t offset,
                                  int64_t bytes, QEMUIOVector *qiov,
                                  BdrvRequestFlags flags)
{
    return qemu_rawstor_start_co(
        bs, offset, bytes, qiov, flags, rawstor_object_pwritev);
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
        // printf("Failed to initialize rawstor\n");
        /**
         * TODO: We have to return fatal error somewhere.
         */
        return;
    }
    bdrv_register(&bdrv_rawstor);
}

block_init(bdrv_rawstor_init);
