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


typedef struct {
    RawstorUUID object_id;
    RawstorObject *object;
    int input_fd;
    int output_fd;
    int event;
    QemuMutex iosync_mutex;
    int iosync_pending_tasks;
    QemuCond iosync_cond;
    QemuThread eventloop;
} BDRVRawstorState;


int RAWSTOR_EVENT_STOP = 1;
int RAWSTOR_EVENT_PAUSE = 2;


typedef struct RawstorTask {
    int ioid;
    BlockDriverState *bs;
    AioContext *ctx;
    Coroutine *co;
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


static int event_handler(RawstorIOEvent *event, void *opaque) {
    printf("rawstor eventloop thread: %s(): start\n", __FUNCTION__);
    BDRVRawstorState *s = opaque;
    printf("rawstor eventloop thread: %s(): rawstor_io_event_error()\n", __FUNCTION__);
    if (rawstor_io_event_error(event) != 0) {
        errno = rawstor_io_event_error(event);
        return -errno;
    }
    printf("rawstor eventloop thread: %s(): rawstor_io_event_result()\n", __FUNCTION__);
    printf("rawstor eventloop thread: %s(): rawstor_io_event_size()\n", __FUNCTION__);
    if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
        errno = EIO;
        return -errno;
    }
    if (s->event == RAWSTOR_EVENT_PAUSE) {
        while (s->iosync_pending_tasks) {
            printf("rawstor eventloop thread: %s(): qemu_cond_wait()\n", __FUNCTION__);
            qemu_cond_wait(&s->iosync_cond, &s->iosync_mutex);
        }
        printf("rawstor eventloop thread: %s(): rawstor_fd_read()\n", __FUNCTION__);
        rawstor_fd_read(
            s->input_fd, &s->event, sizeof(s->event), event_handler, s);
            printf("rawstor eventloop thread: %s(): stop1\n", __FUNCTION__);
        return 0;
    }
    if (s->event == RAWSTOR_EVENT_STOP) {
        // TODO: Better error handler here
        printf("rawstor eventloop thread: %s(): stop2\n", __FUNCTION__);
        return -1;
    }
    // unexpected event
    // TODO: Better error handler here
    printf("rawstor eventloop thread: %s(): stop3\n", __FUNCTION__);
    return -1;
}


static void* eventloop_thread(void *opaque) {
    printf("rawstor eventloop thread: %s(): start\n", __FUNCTION__);
    BDRVRawstorState *s = opaque;

    printf("rawstor eventloop thread: %s(): qemu_mutex_lock()\n", __FUNCTION__);
    qemu_mutex_lock(&s->iosync_mutex);
    printf("rawstor eventloop thread: %s(): rawstor_fd_read()\n", __FUNCTION__);
    rawstor_fd_read(s->input_fd, &s->event, sizeof(s->event), event_handler, s);
    while (true) {
        printf("rawstor eventloop thread: %s(): rawstor_wait_event()\n", __FUNCTION__);
        RawstorIOEvent *event = rawstor_wait_event();
        if (event == NULL) {
            break;
        }
        printf("rawstor eventloop thread: %s(): rawstor_dispatch_event()\n", __FUNCTION__);
        int rval = rawstor_dispatch_event(event);
        printf("rawstor eventloop thread: %s(): rawstor_release_event()\n", __FUNCTION__);
        rawstor_release_event(event);
        if (rval < 0) {
            /**
             * TODO: What should we do here when event dispatcher
             * returns an error?
             */
            errno = -rval;
            perror("rawstor_dispatch_event() failed");
        }
    }
    printf("rawstor eventloop thread: %s(): qemu_mutex_unlock()\n", __FUNCTION__);
    qemu_mutex_unlock(&s->iosync_mutex);
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

    BDRVRawstorState *s = bs->opaque;
    s->object_id = object_id;
    s->object = object;
    s->input_fd = filedes[0];
    s->output_fd = filedes[1];
    s->iosync_pending_tasks = 0;
    
    printf("qemu thread: %s(): qemu_mutex_init()\n", __FUNCTION__);
    qemu_mutex_init(&s->iosync_mutex);
    printf("qemu thread: %s(): qemu_cond_init()\n", __FUNCTION__);
    qemu_cond_init(&s->iosync_cond);

    printf("qemu thread: %s(): qemu_thread_create()\n", __FUNCTION__);
    qemu_thread_create(
        &s->eventloop,
        "block/rawstor/eventloop_thread", eventloop_thread, s,
        QEMU_THREAD_JOINABLE);

    qemu_opts_del(opts);

    return 0;
}


static void qemu_rawstor_close(BlockDriverState *bs) {
    BDRVRawstorState *s = bs->opaque;

    int res = write(
        s->output_fd, &RAWSTOR_EVENT_STOP, sizeof(RAWSTOR_EVENT_STOP));
    if (res != sizeof(RAWSTOR_EVENT_STOP)) {
        perror("write() failed");
    } else {
        qemu_thread_join(&s->eventloop);
    }

    qemu_cond_destroy(&s->iosync_cond);
    qemu_mutex_destroy(&s->iosync_mutex);

    rawstor_object_close(s->object);
    close(s->input_fd);
    close(s->output_fd);
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


static void qemu_rawstor_bh_wake_cb(void *opaque) {
    // printf("%s() <<<\n", __FUNCTION__);
    RawstorTask *task = (RawstorTask*)opaque;
    printf("[%s] qemu eventloop thread: %s(): start\n", task->ioid, __FUNCTION__);
    printf("[%d] qemu eventloop thread: %s(): aio_co_wake()\n", task->ioid, __FUNCTION__);
    aio_co_wake(task->co);
    printf("[%d] qemu eventloop thread: %s(): still alive after aio_co_wake()\n", task->ioid, __FUNCTION__);
    // printf("%s() >>>\n", __FUNCTION__);
}


static int qemu_rawstor_completion(
    RawstorObject *object, size_t size, size_t res, int error, void *opaque)
{
    // printf("%s() <<<\n", __FUNCTION__);
    RawstorTask *task = (RawstorTask*)opaque;
    printf("[%d] rawstor eventloop thread: %s(): start\n", task->ioid, __FUNCTION__);
    /**
     * TODO: Handle partial request here.
     */
    printf("[%d] rawstor eventloop thread: %s(): task->completed = 1\n", task->ioid, __FUNCTION__);
    task->completed = 1;
    // printf("%s() >>>\n", __FUNCTION__);

    printf("[%d] rawstor eventloop thread: %s(): aio_bh_schedule_oneshot()\n", task->ioid, __FUNCTION__);
    aio_bh_schedule_oneshot(task->ctx, qemu_rawstor_bh_wake_cb, task);

    return 0;
}


static int
coroutine_fn qemu_rawstor_preadv(BlockDriverState *bs, int64_t offset,
                                 int64_t bytes, QEMUIOVector *qiov,
                                 BdrvRequestFlags flags)
{
    static int ioid = 0;
    // printf("%s() <<<\n", __FUNCTION__);
    BDRVRawstorState *s = bs->opaque;
    RawstorTask task = {
        .ioid = ioid++,
        .bs = bs,
        .ctx = bdrv_get_aio_context(bs),
        .co = qemu_coroutine_self(),
        .completed = 0,
    };

    printf("[%d] qemu thread: %s(): ++iosync_pending_tasks\n", task.ioid, __FUNCTION__);
    ++s->iosync_pending_tasks;

    printf("[%d] qemu thread: %s(): write()\n", task.ioid, __FUNCTION__);
    int res = write(
        s->output_fd, &RAWSTOR_EVENT_PAUSE, sizeof(RAWSTOR_EVENT_PAUSE));
    if (res != sizeof(RAWSTOR_EVENT_PAUSE)) {
        perror("write() failed");
        return -1;
    }

    printf("[%d] qemu thread: %s(): qemu_mutex_lock()\n", task.ioid, __FUNCTION__);
    qemu_mutex_lock(&s->iosync_mutex);

    /**
     * TODO: Do we have to assert(bytes == sum(qiov))?
     */
    printf("[%d] qemu thread: %s(): rawstor_object_preadv()\n", task.ioid, __FUNCTION__);
    if (rawstor_object_preadv(
        s->object,
        qiov->iov, qiov->niov, bytes, offset,
        qemu_rawstor_completion, &task))
    {
        perror("rawstor_object_preadv() failed");
        return -1;
    }

    printf("[%d] qemu thread: %s(): --iosync_pending_tasks\n", task.ioid, __FUNCTION__);
    --s->iosync_pending_tasks;
    printf("[%d] qemu thread: %s(): qemu_cond_signal()\n", task.ioid, __FUNCTION__);
    qemu_cond_signal(&s->iosync_cond);

    printf("[%d] qemu thread: %s(): qemu_mutex_unlock()\n", task.ioid, __FUNCTION__);
    qemu_mutex_unlock(&s->iosync_mutex);
    printf("[%d] qemu thread: %s(): still alive after qemu_mutex_unlock()\n", task.ioid, __FUNCTION__);

    while (!task.completed) {
        printf("[%d] qemu thread: %s(): qemu_coroutine_yield()\n", task.ioid, __FUNCTION__);
        qemu_coroutine_yield();
        printf("[%d] qemu thread: %s(): still alive after qemu_coroutine_yield()\n", task.ioid, __FUNCTION__);
    }

    // printf("%s() >>>\n", __FUNCTION__);
    return 0;
}


static int
coroutine_fn qemu_rawstor_pwritev(BlockDriverState *bs, int64_t offset,
                                  int64_t bytes, QEMUIOVector *qiov,
                                  BdrvRequestFlags flags) {
    // printf("%s() <<<\n", __FUNCTION__);
    BDRVRawstorState *s = bs->opaque;
    RawstorTask task = {
        .ioid = 0,
        .bs = bs,
        .ctx = bdrv_get_aio_context(bs),
        .co = qemu_coroutine_self(),
        .completed = 0,
    };

    printf("%s(): ++iosync_pending_tasks\n", __FUNCTION__);
    ++s->iosync_pending_tasks;

    int res = write(
        s->output_fd, &RAWSTOR_EVENT_PAUSE, sizeof(RAWSTOR_EVENT_PAUSE));
    if (res != sizeof(RAWSTOR_EVENT_PAUSE)) {
        perror("write() failed");
        return -1;
    }

    qemu_mutex_lock(&s->iosync_mutex);

    /**
     * TODO: Do we have to assert(bytes == sum(qiov))?
     */
    if (rawstor_object_pwritev(
        s->object,
        qiov->iov, qiov->niov, bytes, offset,
        qemu_rawstor_completion, &task))
    {
        perror("rawstor_object_pwritev() failed");
        return -1;
    }

    printf("%s(): --iosync_pending_tasks\n", __FUNCTION__);
    --s->iosync_pending_tasks;
    qemu_cond_signal(&s->iosync_cond);
    qemu_mutex_unlock(&s->iosync_mutex);

    while (!task.completed) {
        // printf("%s() call qemu_coroutine_yield()\n", __FUNCTION__);
        qemu_coroutine_yield();
        // printf("%s() after qemu_coroutine_yield()\n", __FUNCTION__);
    }

    // printf("%s() >>>\n", __FUNCTION__);
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
        // printf("Failed to initialize rawstor\n");
        /**
         * TODO: We have to return fatal error somewhere.
         */
        return;
    }
    bdrv_register(&bdrv_rawstor);
}

block_init(bdrv_rawstor_init);
