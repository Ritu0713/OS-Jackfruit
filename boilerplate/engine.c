/*
 * engine.c - Supervised Multi-Container Runtime (User Space)
 *
 * Intentionally partial starter:
 *   - command-line shape is defined
 *   - key runtime data structures are defined
 *   - bounded-buffer skeleton is defined
 *   - supervisor / client split is outlined
 *
 * Students are expected to design:
 *   - the control-plane IPC implementation
 *   - container lifecycle and metadata synchronization
 *   - clone + namespace setup for each container
 *   - producer/consumer behavior for log buffering
 *   - signal handling and graceful shutdown
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "monitor_ioctl.h"

#define STACK_SIZE (1024 * 1024)
#define CONTAINER_ID_LEN 32
#define CONTROL_PATH "/tmp/mini_runtime.sock"
#define LOG_DIR "logs"
#define CONTROL_MESSAGE_LEN 256
#define CHILD_COMMAND_LEN 256
#define LOG_CHUNK_SIZE 4096
#define LOG_BUFFER_CAPACITY 16
#define DEFAULT_SOFT_LIMIT (40UL << 20)
#define DEFAULT_HARD_LIMIT (64UL << 20)

typedef enum {
    CMD_SUPERVISOR = 0,
    CMD_START,
    CMD_RUN,
    CMD_PS,
    CMD_LOGS,
    CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0,
    CONTAINER_RUNNING,
    CONTAINER_STOPPED,
    CONTAINER_KILLED,
    CONTAINER_EXITED
} container_state_t;

typedef struct container_record {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    pid_t host_pid;
    time_t started_at;
    container_state_t state;
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int exit_code;
    int exit_signal;
    int stop_requested;
    int reaped;
    int log_read_fd;
    int producer_started;
    int producer_joined;
    pthread_t producer_thread;
    void *child_stack;
    char log_path[PATH_MAX];
    struct container_record *next;
} container_record_t;

typedef struct {
    char container_id[CONTAINER_ID_LEN];
    size_t length;
    char data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t items[LOG_BUFFER_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    int shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} bounded_buffer_t;

typedef struct {
    command_kind_t kind;
    char container_id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int nice_value;
} control_request_t;

typedef struct {
    int status;
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int nice_value;
    int log_write_fd;
} child_config_t;

typedef struct {
    int server_fd;
    int monitor_fd;
    int should_stop;
    pthread_t logger_thread;
    bounded_buffer_t log_buffer;
    pthread_mutex_t metadata_lock;
    container_record_t *containers;
} supervisor_ctx_t;

typedef struct {
    supervisor_ctx_t *ctx;
    char container_id[CONTAINER_ID_LEN];
    int read_fd;
} producer_arg_t;

static volatile sig_atomic_t g_sigchld = 0;
static volatile sig_atomic_t g_shutdown_requested = 0;
static volatile sig_atomic_t g_run_interrupt = 0;

int child_fn(void *arg);
int register_with_monitor(int monitor_fd,
                          const char *container_id,
                          pid_t host_pid,
                          unsigned long soft_limit_bytes,
                          unsigned long hard_limit_bytes);
int unregister_from_monitor(int monitor_fd, const char *container_id, pid_t host_pid);
void *logging_thread(void *arg);

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s supervisor <base-rootfs>\n"
            "  %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s ps\n"
            "  %s logs <id>\n"
            "  %s stop <id>\n",
            prog, prog, prog, prog, prog, prog);
}

static int parse_mib_flag(const char *flag,
                          const char *value,
                          unsigned long *target_bytes)
{
    char *end = NULL;
    unsigned long mib;

    errno = 0;
    mib = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: %s\n", flag, value);
        return -1;
    }

    if (mib > ULONG_MAX / (1UL << 20)) {
        fprintf(stderr, "Value for %s is too large: %s\n", flag, value);
        return -1;
    }

    *target_bytes = mib * (1UL << 20);
    return 0;
}

static int parse_optional_flags(control_request_t *req,
                                int argc,
                                char *argv[],
                                int start_index)
{
    int i;

    for (i = start_index; i < argc; i += 2) {
        char *end = NULL;
        long nice_value;

        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for option: %s\n", argv[i]);
            return -1;
        }

        if (strcmp(argv[i], "--soft-mib") == 0) {
            if (parse_mib_flag("--soft-mib", argv[i + 1], &req->soft_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--hard-mib") == 0) {
            if (parse_mib_flag("--hard-mib", argv[i + 1], &req->hard_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--nice") == 0) {
            errno = 0;
            nice_value = strtol(argv[i + 1], &end, 10);
            if (errno != 0 || end == argv[i + 1] || *end != '\0' ||
                nice_value < -20 || nice_value > 19) {
                fprintf(stderr,
                        "Invalid value for --nice (expected -20..19): %s\n",
                        argv[i + 1]);
                return -1;
            }
            req->nice_value = (int)nice_value;
            continue;
        }

        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return -1;
    }

    if (req->soft_limit_bytes > req->hard_limit_bytes) {
        fprintf(stderr, "Invalid limits: soft limit cannot exceed hard limit\n");
        return -1;
    }

    return 0;
}

static const char *state_to_string(container_state_t state)
{
    switch (state) {
    case CONTAINER_STARTING:
        return "starting";
    case CONTAINER_RUNNING:
        return "running";
    case CONTAINER_STOPPED:
        return "stopped";
    case CONTAINER_KILLED:
        return "killed";
    case CONTAINER_EXITED:
        return "exited";
    default:
        return "unknown";
    }
}

static int bounded_buffer_init(bounded_buffer_t *buffer)
{
    int rc;

    memset(buffer, 0, sizeof(*buffer));

    rc = pthread_mutex_init(&buffer->mutex, NULL);
    if (rc != 0)
        return rc;

    rc = pthread_cond_init(&buffer->not_empty, NULL);
    if (rc != 0) {
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    rc = pthread_cond_init(&buffer->not_full, NULL);
    if (rc != 0) {
        pthread_cond_destroy(&buffer->not_empty);
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *buffer)
{
    pthread_cond_destroy(&buffer->not_full);
    pthread_cond_destroy(&buffer->not_empty);
    pthread_mutex_destroy(&buffer->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *buffer)
{
    pthread_mutex_lock(&buffer->mutex);
    buffer->shutting_down = 1;
    pthread_cond_broadcast(&buffer->not_empty);
    pthread_cond_broadcast(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
}

static ssize_t write_full(int fd, const void *buf, size_t count)
{
    const char *p = (const char *)buf;
    size_t written = 0;

    while (written < count) {
        ssize_t n = write(fd, p + written, count - written);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        written += (size_t)n;
    }

    return (ssize_t)written;
}

static ssize_t read_full(int fd, void *buf, size_t count)
{
    char *p = (char *)buf;
    size_t done = 0;

    while (done < count) {
        ssize_t n = read(fd, p + done, count - done);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return 0;
        done += (size_t)n;
    }

    return (ssize_t)done;
}

static container_record_t *find_container_by_id_locked(supervisor_ctx_t *ctx,
                                                        const char *id)
{
    container_record_t *cur;

    for (cur = ctx->containers; cur != NULL; cur = cur->next) {
        if (strncmp(cur->id, id, sizeof(cur->id)) == 0)
            return cur;
    }
    return NULL;
}

static container_record_t *find_container_by_pid_locked(supervisor_ctx_t *ctx,
                                                         pid_t pid)
{
    container_record_t *cur;

    for (cur = ctx->containers; cur != NULL; cur = cur->next) {
        if (cur->host_pid == pid)
            return cur;
    }
    return NULL;
}

static int any_running_on_rootfs_locked(supervisor_ctx_t *ctx, const char *rootfs)
{
    container_record_t *cur;

    for (cur = ctx->containers; cur != NULL; cur = cur->next) {
        if ((cur->state == CONTAINER_STARTING || cur->state == CONTAINER_RUNNING) &&
            strncmp(cur->rootfs, rootfs, sizeof(cur->rootfs)) == 0) {
            return 1;
        }
    }
    return 0;
}

static int connect_control_socket(void)
{
    int fd;
    struct sockaddr_un addr;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static int make_log_path(const char *container_id, char *out, size_t out_len)
{
    int rc = snprintf(out, out_len, "%s/%s.log", LOG_DIR, container_id);
    if (rc < 0 || (size_t)rc >= out_len)
        return -1;
    return 0;
}

static void run_signal_handler(int signo)
{
    (void)signo;
    g_run_interrupt = 1;
}

static void supervisor_signal_handler(int signo)
{
    if (signo == SIGCHLD) {
        g_sigchld = 1;
        return;
    }
    if (signo == SIGINT || signo == SIGTERM)
        g_shutdown_requested = 1;
}

static int send_stop_for_container_id(const char *container_id)
{
    int fd;
    control_request_t stop_req;
    control_response_t stop_resp;

    fd = connect_control_socket();
    if (fd < 0)
        return -1;

    memset(&stop_req, 0, sizeof(stop_req));
    stop_req.kind = CMD_STOP;
    strncpy(stop_req.container_id, container_id, sizeof(stop_req.container_id) - 1);

    if (write_full(fd, &stop_req, sizeof(stop_req)) != (ssize_t)sizeof(stop_req)) {
        close(fd);
        return -1;
    }

    if (read_full(fd, &stop_resp, sizeof(stop_resp)) != (ssize_t)sizeof(stop_resp)) {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static int read_response_for_run(int fd,
                                 control_response_t *resp,
                                 const char *container_id)
{
    size_t off = 0;
    int forwarded_stop = 0;

    while (off < sizeof(*resp)) {
        ssize_t n;

        if (g_run_interrupt && !forwarded_stop) {
            (void)send_stop_for_container_id(container_id);
            forwarded_stop = 1;
        }

        n = recv(fd, (char *)resp + off, sizeof(*resp) - off, MSG_DONTWAIT);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }

        if (n == 0)
            return -1;

        if (errno == EINTR)
            continue;

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            usleep(100000);
            continue;
        }

        return -1;
    }

    return 0;
}

static void cleanup_container_runtime_fields(supervisor_ctx_t *ctx,
                                             container_record_t *rec)
{
    if (ctx->monitor_fd >= 0)
        (void)unregister_from_monitor(ctx->monitor_fd, rec->id, rec->host_pid);

    if (rec->log_read_fd >= 0) {
        close(rec->log_read_fd);
        rec->log_read_fd = -1;
    }

    if (rec->producer_started && !rec->producer_joined) {
        pthread_join(rec->producer_thread, NULL);
        rec->producer_joined = 1;
    }

    if (rec->child_stack != NULL) {
        free(rec->child_stack);
        rec->child_stack = NULL;
    }
}

static void reap_children(supervisor_ctx_t *ctx)
{
    for (;;) {
        int status;
        pid_t pid;
        container_record_t *rec;

        pid = waitpid(-1, &status, WNOHANG);
        if (pid <= 0)
            break;

        pthread_mutex_lock(&ctx->metadata_lock);
        rec = find_container_by_pid_locked(ctx, pid);
        if (rec == NULL || rec->reaped) {
            pthread_mutex_unlock(&ctx->metadata_lock);
            continue;
        }

        rec->reaped = 1;
        if (WIFEXITED(status)) {
            rec->exit_code = WEXITSTATUS(status);
            rec->exit_signal = 0;
            rec->state = CONTAINER_EXITED;
        } else if (WIFSIGNALED(status)) {
            rec->exit_signal = WTERMSIG(status);
            rec->exit_code = 128 + rec->exit_signal;
            if (rec->stop_requested)
                rec->state = CONTAINER_STOPPED;
            else
                rec->state = CONTAINER_KILLED;
        } else {
            rec->exit_code = 1;
            rec->exit_signal = 0;
            rec->state = CONTAINER_EXITED;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);

        cleanup_container_runtime_fields(ctx, rec);
    }
}

static void free_all_containers(supervisor_ctx_t *ctx)
{
    container_record_t *cur;

    cur = ctx->containers;
    while (cur != NULL) {
        container_record_t *next = cur->next;
        if (cur->log_read_fd >= 0)
            close(cur->log_read_fd);
        if (cur->producer_started && !cur->producer_joined)
            pthread_join(cur->producer_thread, NULL);
        if (cur->child_stack != NULL)
            free(cur->child_stack);
        free(cur);
        cur = next;
    }
    ctx->containers = NULL;
}

static void graceful_stop_running(supervisor_ctx_t *ctx)
{
    int i;

    pthread_mutex_lock(&ctx->metadata_lock);
    {
        container_record_t *cur;
        for (cur = ctx->containers; cur != NULL; cur = cur->next) {
            if (cur->state == CONTAINER_STARTING || cur->state == CONTAINER_RUNNING) {
                cur->stop_requested = 1;
                kill(cur->host_pid, SIGTERM);
            }
        }
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    for (i = 0; i < 30; ++i) {
        reap_children(ctx);
        usleep(100000);
    }

    pthread_mutex_lock(&ctx->metadata_lock);
    {
        container_record_t *cur;
        for (cur = ctx->containers; cur != NULL; cur = cur->next) {
            if (cur->state == CONTAINER_STARTING || cur->state == CONTAINER_RUNNING)
                kill(cur->host_pid, SIGKILL);
        }
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    for (i = 0; i < 20; ++i) {
        reap_children(ctx);
        usleep(100000);
    }
}

static int wait_for_container_exit(supervisor_ctx_t *ctx,
                                   const char *container_id,
                                   control_response_t *resp)
{
    for (;;) {
        container_record_t *rec;
        int done = 0;

        pthread_mutex_lock(&ctx->metadata_lock);
        rec = find_container_by_id_locked(ctx, container_id);
        if (rec == NULL) {
            pthread_mutex_unlock(&ctx->metadata_lock);
            resp->status = 1;
            snprintf(resp->message,
                     sizeof(resp->message),
                     "Container disappeared: %s",
                     container_id);
            return -1;
        }

        if (rec->state != CONTAINER_STARTING && rec->state != CONTAINER_RUNNING) {
            done = 1;
            resp->status = rec->exit_code;
            snprintf(resp->message,
                     sizeof(resp->message),
                     "Container %s finished state=%s exit_code=%d signal=%d",
                     rec->id,
                     state_to_string(rec->state),
                     rec->exit_code,
                     rec->exit_signal);
        }
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (done)
            return 0;

        reap_children(ctx);
        usleep(100000);
    }
}

static int start_container(supervisor_ctx_t *ctx,
                           const control_request_t *req,
                           control_response_t *resp)
{
    int log_pipe[2] = {-1, -1};
    int clone_flags;
    pid_t pid;
    void *stack = NULL;
    child_config_t *cfg = NULL;
    producer_arg_t *producer_arg = NULL;
    container_record_t *rec = NULL;

    if (req->container_id[0] == '\0') {
        resp->status = 1;
        snprintf(resp->message, sizeof(resp->message), "Container id cannot be empty");
        return -1;
    }

    pthread_mutex_lock(&ctx->metadata_lock);
    if (find_container_by_id_locked(ctx, req->container_id) != NULL) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        resp->status = 1;
        snprintf(resp->message,
                 sizeof(resp->message),
                 "Container id already exists: %s",
                 req->container_id);
        return -1;
    }
    if (any_running_on_rootfs_locked(ctx, req->rootfs)) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        resp->status = 1;
        snprintf(resp->message,
                 sizeof(resp->message),
                 "Rootfs already in use by another running container");
        return -1;
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    if (mkdir(LOG_DIR, 0755) < 0 && errno != EEXIST) {
        resp->status = 1;
        snprintf(resp->message, sizeof(resp->message), "Failed to create logs directory");
        return -1;
    }

    if (pipe(log_pipe) < 0) {
        resp->status = 1;
        snprintf(resp->message, sizeof(resp->message), "pipe failed: %s", strerror(errno));
        return -1;
    }

    stack = malloc(STACK_SIZE);
    if (stack == NULL) {
        resp->status = 1;
        snprintf(resp->message, sizeof(resp->message), "malloc stack failed");
        close(log_pipe[0]);
        close(log_pipe[1]);
        return -1;
    }

    cfg = calloc(1, sizeof(*cfg));
    if (cfg == NULL) {
        resp->status = 1;
        snprintf(resp->message, sizeof(resp->message), "malloc child config failed");
        close(log_pipe[0]);
        close(log_pipe[1]);
        free(stack);
        return -1;
    }

    strncpy(cfg->id, req->container_id, sizeof(cfg->id) - 1);
    strncpy(cfg->rootfs, req->rootfs, sizeof(cfg->rootfs) - 1);
    strncpy(cfg->command, req->command, sizeof(cfg->command) - 1);
    cfg->nice_value = req->nice_value;
    cfg->log_write_fd = log_pipe[1];

    clone_flags = SIGCHLD | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS;
    pid = clone(child_fn, (char *)stack + STACK_SIZE, clone_flags, cfg);
    if (pid < 0) {
        resp->status = 1;
        snprintf(resp->message, sizeof(resp->message), "clone failed: %s", strerror(errno));
        close(log_pipe[0]);
        close(log_pipe[1]);
        free(stack);
        free(cfg);
        return -1;
    }

    close(log_pipe[1]);
    free(cfg);

    rec = calloc(1, sizeof(*rec));
    if (rec == NULL) {
        kill(pid, SIGKILL);
        close(log_pipe[0]);
        free(stack);
        resp->status = 1;
        snprintf(resp->message, sizeof(resp->message), "malloc container record failed");
        return -1;
    }

    strncpy(rec->id, req->container_id, sizeof(rec->id) - 1);
    strncpy(rec->rootfs, req->rootfs, sizeof(rec->rootfs) - 1);
    rec->host_pid = pid;
    rec->started_at = time(NULL);
    rec->state = CONTAINER_RUNNING;
    rec->soft_limit_bytes = req->soft_limit_bytes;
    rec->hard_limit_bytes = req->hard_limit_bytes;
    rec->log_read_fd = log_pipe[0];
    rec->child_stack = stack;
    if (make_log_path(rec->id, rec->log_path, sizeof(rec->log_path)) != 0)
        strncpy(rec->log_path, "logs/unknown.log", sizeof(rec->log_path) - 1);

    pthread_mutex_lock(&ctx->metadata_lock);
    rec->next = ctx->containers;
    ctx->containers = rec;
    pthread_mutex_unlock(&ctx->metadata_lock);

    producer_arg = calloc(1, sizeof(*producer_arg));
    if (producer_arg == NULL) {
        rec->stop_requested = 1;
        kill(pid, SIGTERM);
        resp->status = 1;
        snprintf(resp->message, sizeof(resp->message), "malloc producer arg failed");
        return -1;
    }

    producer_arg->ctx = ctx;
    producer_arg->read_fd = log_pipe[0];
    strncpy(producer_arg->container_id,
            req->container_id,
            sizeof(producer_arg->container_id) - 1);

    if (pthread_create(&rec->producer_thread, NULL, logging_thread, producer_arg) != 0) {
        rec->stop_requested = 1;
        kill(pid, SIGTERM);
        free(producer_arg);
        resp->status = 1;
        snprintf(resp->message, sizeof(resp->message), "failed to spawn log producer");
        return -1;
    }
    rec->producer_started = 1;

    if (ctx->monitor_fd >= 0) {
        if (register_with_monitor(ctx->monitor_fd,
                                  rec->id,
                                  rec->host_pid,
                                  rec->soft_limit_bytes,
                                  rec->hard_limit_bytes) < 0) {
            fprintf(stderr,
                    "warning: monitor register failed for %s (pid=%d): %s\n",
                    rec->id,
                    rec->host_pid,
                    strerror(errno));
        }
    }

    resp->status = 0;
    snprintf(resp->message,
             sizeof(resp->message),
             "Started container %s pid=%d",
             rec->id,
             rec->host_pid);
    return 0;
}

static int build_ps_message(supervisor_ctx_t *ctx, char *out, size_t out_len)
{
    size_t used = 0;
    container_record_t *cur;

    pthread_mutex_lock(&ctx->metadata_lock);
    cur = ctx->containers;
    if (cur == NULL) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        snprintf(out, out_len, "No tracked containers");
        return 0;
    }

    out[0] = '\0';
    while (cur != NULL) {
        char line[192];
        int n = snprintf(line,
                         sizeof(line),
                         "%s pid=%d state=%s exit=%d sig=%d\n",
                         cur->id,
                         cur->host_pid,
                         state_to_string(cur->state),
                         cur->exit_code,
                         cur->exit_signal);
        if (n < 0)
            break;
        if (used + (size_t)n + 1 >= out_len) {
            snprintf(out + used, out_len - used, "...truncated...");
            break;
        }
        memcpy(out + used, line, (size_t)n);
        used += (size_t)n;
        out[used] = '\0';
        cur = cur->next;
    }
    pthread_mutex_unlock(&ctx->metadata_lock);
    return 0;
}

static int handle_control_request(supervisor_ctx_t *ctx,
                                  const control_request_t *req,
                                  control_response_t *resp)
{
    memset(resp, 0, sizeof(*resp));

    switch (req->kind) {
    case CMD_START:
        return start_container(ctx, req, resp);

    case CMD_RUN:
        if (start_container(ctx, req, resp) != 0)
            return -1;
        return wait_for_container_exit(ctx, req->container_id, resp);

    case CMD_PS:
        reap_children(ctx);
        resp->status = 0;
        return build_ps_message(ctx, resp->message, sizeof(resp->message));

    case CMD_LOGS: {
        container_record_t *rec;
        pthread_mutex_lock(&ctx->metadata_lock);
        rec = find_container_by_id_locked(ctx, req->container_id);
        if (rec == NULL) {
            pthread_mutex_unlock(&ctx->metadata_lock);
            resp->status = 1;
            snprintf(resp->message,
                     sizeof(resp->message),
                     "Container not found: %s",
                     req->container_id);
            return -1;
        }
        resp->status = 0;
        strncpy(resp->message, rec->log_path, sizeof(resp->message) - 1);
        pthread_mutex_unlock(&ctx->metadata_lock);
        return 0;
    }

    case CMD_STOP: {
        container_record_t *rec;
        pthread_mutex_lock(&ctx->metadata_lock);
        rec = find_container_by_id_locked(ctx, req->container_id);
        if (rec == NULL) {
            pthread_mutex_unlock(&ctx->metadata_lock);
            resp->status = 1;
            snprintf(resp->message,
                     sizeof(resp->message),
                     "Container not found: %s",
                     req->container_id);
            return -1;
        }

        if (rec->state != CONTAINER_STARTING && rec->state != CONTAINER_RUNNING) {
            resp->status = 1;
            snprintf(resp->message,
                     sizeof(resp->message),
                     "Container %s is not running (state=%s)",
                     rec->id,
                     state_to_string(rec->state));
            pthread_mutex_unlock(&ctx->metadata_lock);
            return -1;
        }

        rec->stop_requested = 1;
        if (kill(rec->host_pid, SIGTERM) < 0) {
            resp->status = 1;
            snprintf(resp->message,
                     sizeof(resp->message),
                     "Failed to signal container %s: %s",
                     rec->id,
                     strerror(errno));
            pthread_mutex_unlock(&ctx->metadata_lock);
            return -1;
        }
        resp->status = 0;
        snprintf(resp->message, sizeof(resp->message), "Stop requested for %s", rec->id);
        pthread_mutex_unlock(&ctx->metadata_lock);
        return 0;
    }

    default:
        resp->status = 1;
        snprintf(resp->message, sizeof(resp->message), "Unknown command kind: %d", req->kind);
        return -1;
    }
}

/*
 * TODO:
 * Implement producer-side insertion into the bounded buffer.
 *
 * Requirements:
 *   - block or fail according to your chosen policy when the buffer is full
 *   - wake consumers correctly
 *   - stop cleanly if shutdown begins
 */
int bounded_buffer_push(bounded_buffer_t *buffer, const log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);
    while (buffer->count == LOG_BUFFER_CAPACITY && !buffer->shutting_down)
        pthread_cond_wait(&buffer->not_full, &buffer->mutex);

    if (buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }

    buffer->items[buffer->tail] = *item;
    buffer->tail = (buffer->tail + 1) % LOG_BUFFER_CAPACITY;
    buffer->count++;
    pthread_cond_signal(&buffer->not_empty);
    pthread_mutex_unlock(&buffer->mutex);

    return 0;
}

/*
 * TODO:
 * Implement consumer-side removal from the bounded buffer.
 *
 * Requirements:
 *   - wait correctly while the buffer is empty
 *   - return a useful status when shutdown is in progress
 *   - avoid races with producers and shutdown
 */
int bounded_buffer_pop(bounded_buffer_t *buffer, log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);
    while (buffer->count == 0 && !buffer->shutting_down)
        pthread_cond_wait(&buffer->not_empty, &buffer->mutex);

    if (buffer->count == 0 && buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return 1;
    }

    *item = buffer->items[buffer->head];
    buffer->head = (buffer->head + 1) % LOG_BUFFER_CAPACITY;
    buffer->count--;
    pthread_cond_signal(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);

    return 0;
}

/*
 * TODO:
 * Implement the logging consumer thread.
 *
 * Suggested responsibilities:
 *   - remove log chunks from the bounded buffer
 *   - route each chunk to the correct per-container log file
 *   - exit cleanly when shutdown begins and pending work is drained
 */
void *logging_thread(void *arg)
{
    producer_arg_t *producer = (producer_arg_t *)arg;
    supervisor_ctx_t *ctx = producer->ctx;
    log_item_t item;

    memset(&item, 0, sizeof(item));
    strncpy(item.container_id, producer->container_id, sizeof(item.container_id) - 1);

    for (;;) {
        ssize_t n = read(producer->read_fd, item.data, sizeof(item.data));
        if (n > 0) {
            item.length = (size_t)n;
            if (bounded_buffer_push(&ctx->log_buffer, &item) != 0)
                break;
            continue;
        }

        if (n == 0)
            break;

        if (errno == EINTR)
            continue;

        break;
    }

    close(producer->read_fd);
    free(producer);
    return NULL;
}

static void *log_consumer_thread(void *arg)
{
    supervisor_ctx_t *ctx = (supervisor_ctx_t *)arg;

    for (;;) {
        log_item_t item;
        int rc;
        char log_path[PATH_MAX];
        int fd;

        rc = bounded_buffer_pop(&ctx->log_buffer, &item);
        if (rc == 1)
            break;
        if (rc != 0)
            continue;

        if (make_log_path(item.container_id, log_path, sizeof(log_path)) != 0)
            continue;

        fd = open(log_path, O_CREAT | O_WRONLY | O_APPEND, 0644);
        if (fd < 0)
            continue;

        if (item.length > 0)
            (void)write_full(fd, item.data, item.length);

        close(fd);
    }

    return NULL;
}

/*
 * TODO:
 * Implement the clone child entrypoint.
 *
 * Required outcomes:
 *   - isolated PID / UTS / mount context
 *   - chroot or pivot_root into rootfs
 *   - working /proc inside container
 *   - stdout / stderr redirected to the supervisor logging path
 *   - configured command executed inside the container
 */
int child_fn(void *arg)
{
    child_config_t *cfg = (child_config_t *)arg;
    int devnull;

    if (cfg == NULL)
        return 1;

    if (dup2(cfg->log_write_fd, STDOUT_FILENO) < 0)
        return 1;
    if (dup2(cfg->log_write_fd, STDERR_FILENO) < 0)
        return 1;
    close(cfg->log_write_fd);

    devnull = open("/dev/null", O_RDONLY);
    if (devnull >= 0) {
        (void)dup2(devnull, STDIN_FILENO);
        close(devnull);
    }

    (void)sethostname(cfg->id, strnlen(cfg->id, sizeof(cfg->id)));
    (void)setpriority(PRIO_PROCESS, 0, cfg->nice_value);

    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
        perror("mount-private");

    if (chdir(cfg->rootfs) < 0) {
        perror("chdir rootfs");
        return 1;
    }
    if (chroot(".") < 0) {
        perror("chroot");
        return 1;
    }
    if (chdir("/") < 0) {
        perror("chdir /");
        return 1;
    }

    if (mkdir("/proc", 0555) < 0 && errno != EEXIST) {
        perror("mkdir /proc");
        return 1;
    }
    if (mount("proc", "/proc", "proc", 0, NULL) < 0)
        perror("mount /proc");

    execl("/bin/sh", "sh", "-c", cfg->command, (char *)NULL);
    perror("exec");
    return 1;
}

int register_with_monitor(int monitor_fd,
                          const char *container_id,
                          pid_t host_pid,
                          unsigned long soft_limit_bytes,
                          unsigned long hard_limit_bytes)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    req.soft_limit_bytes = soft_limit_bytes;
    req.hard_limit_bytes = hard_limit_bytes;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0)
        return -1;

    return 0;
}

int unregister_from_monitor(int monitor_fd, const char *container_id, pid_t host_pid)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0)
        return -1;

    return 0;
}

/*
 * TODO:
 * Implement the long-running supervisor process.
 *
 * Suggested responsibilities:
 *   - create and bind the control-plane IPC endpoint
 *   - initialize shared metadata and the bounded buffer
 *   - start the logging thread
 *   - accept control requests and update container state
 *   - reap children and respond to signals
 */
static int run_supervisor(const char *rootfs)
{
    supervisor_ctx_t ctx;
    struct sockaddr_un addr;
    struct sigaction sa;
    int rc;

    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd = -1;
    ctx.monitor_fd = -1;

    rc = pthread_mutex_init(&ctx.metadata_lock, NULL);
    if (rc != 0) {
        errno = rc;
        perror("pthread_mutex_init");
        return 1;
    }

    rc = bounded_buffer_init(&ctx.log_buffer);
    if (rc != 0) {
        errno = rc;
        perror("bounded_buffer_init");
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    if (mkdir(LOG_DIR, 0755) < 0 && errno != EEXIST)
        perror("mkdir logs");

    ctx.monitor_fd = open("/dev/container_monitor", O_RDWR);
    if (ctx.monitor_fd < 0) {
        fprintf(stderr,
                "warning: monitor device unavailable (%s); continuing without kernel monitor\n",
                strerror(errno));
    }

    unlink(CONTROL_PATH);
    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx.server_fd < 0) {
        perror("socket");
        if (ctx.monitor_fd >= 0)
            close(ctx.monitor_fd);
        bounded_buffer_destroy(&ctx.log_buffer);
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(ctx.server_fd);
        if (ctx.monitor_fd >= 0)
            close(ctx.monitor_fd);
        bounded_buffer_destroy(&ctx.log_buffer);
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    if (listen(ctx.server_fd, 16) < 0) {
        perror("listen");
        close(ctx.server_fd);
        unlink(CONTROL_PATH);
        if (ctx.monitor_fd >= 0)
            close(ctx.monitor_fd);
        bounded_buffer_destroy(&ctx.log_buffer);
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = supervisor_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGCHLD, &sa, NULL) < 0 ||
        sigaction(SIGINT, &sa, NULL) < 0 ||
        sigaction(SIGTERM, &sa, NULL) < 0) {
        perror("sigaction");
        close(ctx.server_fd);
        unlink(CONTROL_PATH);
        if (ctx.monitor_fd >= 0)
            close(ctx.monitor_fd);
        bounded_buffer_destroy(&ctx.log_buffer);
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    rc = pthread_create(&ctx.logger_thread, NULL, log_consumer_thread, &ctx);
    if (rc != 0) {
        errno = rc;
        perror("pthread_create logger");
        close(ctx.server_fd);
        unlink(CONTROL_PATH);
        if (ctx.monitor_fd >= 0)
            close(ctx.monitor_fd);
        bounded_buffer_destroy(&ctx.log_buffer);
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    fprintf(stderr,
            "Supervisor listening on %s with base-rootfs=%s\n",
            CONTROL_PATH,
            rootfs);

    while (!ctx.should_stop) {
        int client_fd;
        control_request_t req;
        control_response_t resp;

        if (g_shutdown_requested)
            ctx.should_stop = 1;

        if (g_sigchld) {
            g_sigchld = 0;
            reap_children(&ctx);
        }

        if (ctx.should_stop)
            break;

        client_fd = accept(ctx.server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR)
                continue;
            perror("accept");
            break;
        }

        if (read_full(client_fd, &req, sizeof(req)) != (ssize_t)sizeof(req)) {
            close(client_fd);
            continue;
        }

        (void)handle_control_request(&ctx, &req, &resp);

        if (write_full(client_fd, &resp, sizeof(resp)) != (ssize_t)sizeof(resp))
            perror("write response");

        close(client_fd);
    }

    graceful_stop_running(&ctx);

    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    pthread_join(ctx.logger_thread, NULL);

    free_all_containers(&ctx);

    if (ctx.server_fd >= 0)
        close(ctx.server_fd);
    unlink(CONTROL_PATH);

    if (ctx.monitor_fd >= 0)
        close(ctx.monitor_fd);

    bounded_buffer_destroy(&ctx.log_buffer);
    pthread_mutex_destroy(&ctx.metadata_lock);
    return 0;
}

/*
 * TODO:
 * Implement the client-side control request path.
 *
 * The CLI commands should use a second IPC mechanism distinct from the
 * logging pipe. A UNIX domain socket is the most direct option, but a
 * FIFO or shared memory design is also acceptable if justified.
 */
static int send_control_request(const control_request_t *req)
{
    int fd;
    control_response_t resp;

    fd = connect_control_socket();
    if (fd < 0) {
        fprintf(stderr,
                "Failed to connect supervisor at %s: %s\n",
                CONTROL_PATH,
                strerror(errno));
        return 1;
    }

    if (write_full(fd, req, sizeof(*req)) != (ssize_t)sizeof(*req)) {
        fprintf(stderr, "Failed to send request: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    memset(&resp, 0, sizeof(resp));

    if (req->kind == CMD_RUN) {
        struct sigaction old_int;
        struct sigaction old_term;
        struct sigaction sa;

        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = run_signal_handler;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGINT, &sa, &old_int);
        sigaction(SIGTERM, &sa, &old_term);

        g_run_interrupt = 0;
        if (read_response_for_run(fd, &resp, req->container_id) != 0) {
            fprintf(stderr, "Failed while waiting for run response\n");
            sigaction(SIGINT, &old_int, NULL);
            sigaction(SIGTERM, &old_term, NULL);
            close(fd);
            return 1;
        }

        sigaction(SIGINT, &old_int, NULL);
        sigaction(SIGTERM, &old_term, NULL);
    } else {
        if (read_full(fd, &resp, sizeof(resp)) != (ssize_t)sizeof(resp)) {
            fprintf(stderr, "Failed to read response: %s\n", strerror(errno));
            close(fd);
            return 1;
        }
    }

    close(fd);

    if (req->kind == CMD_LOGS && resp.status == 0) {
        int log_fd = open(resp.message, O_RDONLY);
        if (log_fd < 0) {
            fprintf(stderr, "Failed to open log file %s: %s\n", resp.message, strerror(errno));
            return 1;
        }

        for (;;) {
            char buf[LOG_CHUNK_SIZE];
            ssize_t n = read(log_fd, buf, sizeof(buf));
            if (n > 0) {
                if (write_full(STDOUT_FILENO, buf, (size_t)n) < 0) {
                    close(log_fd);
                    fprintf(stderr, "Failed to print logs\n");
                    return 1;
                }
                continue;
            }
            if (n == 0)
                break;
            if (errno == EINTR)
                continue;
            close(log_fd);
            fprintf(stderr, "Failed to read logs: %s\n", strerror(errno));
            return 1;
        }

        close(log_fd);
        return 0;
    }

    if (resp.message[0] != '\0')
        printf("%s\n", resp.message);

    if (req->kind == CMD_RUN)
        return resp.status;

    return (resp.status == 0) ? 0 : 1;
}

static int cmd_start(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_START;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req);
}

static int cmd_run(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_RUN;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req);
}

static int cmd_ps(void)
{
    control_request_t req;

    memset(&req, 0, sizeof(req));
    req.kind = CMD_PS;

    /*
     * TODO:
     * The supervisor should respond with container metadata.
     * Keep the rendering format simple enough for demos and debugging.
     */
    printf("Expected states include: %s, %s, %s, %s, %s\n",
           state_to_string(CONTAINER_STARTING),
           state_to_string(CONTAINER_RUNNING),
           state_to_string(CONTAINER_STOPPED),
           state_to_string(CONTAINER_KILLED),
           state_to_string(CONTAINER_EXITED));
    return send_control_request(&req);
}

static int cmd_logs(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s logs <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_LOGS;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);

    return send_control_request(&req);
}

static int cmd_stop(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s stop <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_STOP;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);

    return send_control_request(&req);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "supervisor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s supervisor <base-rootfs>\n", argv[0]);
            return 1;
        }
        return run_supervisor(argv[2]);
    }

    if (strcmp(argv[1], "start") == 0)
        return cmd_start(argc, argv);

    if (strcmp(argv[1], "run") == 0)
        return cmd_run(argc, argv);

    if (strcmp(argv[1], "ps") == 0)
        return cmd_ps();

    if (strcmp(argv[1], "logs") == 0)
        return cmd_logs(argc, argv);

    if (strcmp(argv[1], "stop") == 0)
        return cmd_stop(argc, argv);

    usage(argv[0]);
    return 1;
}
