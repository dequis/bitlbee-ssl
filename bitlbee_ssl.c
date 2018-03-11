// gcc -g -shared -fPIC $(pkg-config --cflags bitlbee) bitlbee_ssl.c -o bitlbee_ssl.so

#include <bitlbee.h>
#include <gio/gio.h>

#define DEBUG 0
#define BUDDY "peer"

typedef enum {
    STATUS_INITIAL,
    STATUS_HEADERS,
    STATUS_BODY,
} http_req_status;

typedef struct {
    struct im_connection *ic;
    GSocketConnection *connection;
    http_req_status status;
    size_t content_length;
} http_state_t;

static void
http_send_response(http_state_t *http_state, char *status, char *body)
{
    GSocketConnection *connection = http_state->connection;
    GOutputStream *ostream = g_io_stream_get_output_stream(G_IO_STREAM(connection));

    char *buf = g_strdup_printf("HTTP/1.1 %s\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "%s",
        status, body);

    g_output_stream_write_all(ostream, buf, strlen(buf), NULL, NULL, NULL);

    g_free(buf);
}

static void
http_close_connection(http_state_t *http_state)
{
    g_io_stream_close(G_IO_STREAM(http_state->connection), NULL, NULL);
    g_object_unref(http_state->connection);
    http_state->connection = NULL;
    g_free(http_state);
}

static gboolean
http_error_400(http_state_t *http_state)
{
    http_send_response(http_state, "400 Bad Request", "bad");
    http_close_connection(http_state);
    return FALSE;
}

static char *
http_parse_header_inplace(char *input)
{
    char *colon = strchr(input, ':');

    if (!colon) {
        return NULL;
    }

    *colon = '\0';
    return g_strstrip(colon + 1);
}

static void
http_got_body_cb(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
    GBytes *bytes;
    gsize size;
    gpointer input_data;
    char *stringy;
    http_state_t *http_state = user_data;
    struct im_connection *ic = http_state->ic;

    bytes = g_input_stream_read_bytes_finish(G_INPUT_STREAM(source_object), res, NULL);

    if (!bytes) {
        http_error_400(http_state);
        return;
    }

    input_data = g_bytes_unref_to_data(bytes, &size);
    stringy = g_strndup(input_data, size);

    if (DEBUG) {
        imcb_buddy_msg(ic, BUDDY, "BODY:", 0, 0);
    }

    imcb_buddy_msg(ic, BUDDY, stringy, 0, 0);

    g_free(input_data);
    g_free(stringy);

    http_send_response(http_state, "200 OK", "ok");
    http_close_connection(http_state);
}

static gboolean
http_read_line(http_state_t *http_state, struct im_connection *ic, GDataInputStream *gdi)
{
    char *message = g_data_input_stream_read_line_utf8(gdi, NULL, NULL, NULL);

    if (!message) {
        return FALSE;
    }

    if (DEBUG) {
        imcb_buddy_msg(ic, BUDDY, message, 0, 0);
    }

    switch (http_state->status) {
        case STATUS_INITIAL:
            if (!g_str_has_prefix(message, "POST / ") ) {
                g_free(message);
                return http_error_400(http_state);
            }
            http_state->status = STATUS_HEADERS;
            break;

        case STATUS_HEADERS:
            if (*message != '\0') {
                char *value = http_parse_header_inplace(message);

                if (g_strcasecmp(message, "content-length") == 0) {
                    int len = atoi(value);
                    if (len < 0 || len > 1024*1024) {
                        g_free(message);
                        return http_error_400(http_state);
                    }
                    http_state->content_length = len;
                }

            } else {
                http_state->status = STATUS_BODY;

                g_free(message);

                if (http_state->content_length == 0) {
                    return http_error_400(http_state);
                }

                g_input_stream_read_bytes_async(G_INPUT_STREAM(gdi), http_state->content_length,
                    G_PRIORITY_DEFAULT, NULL, http_got_body_cb, http_state);

                return FALSE;
            }
            break;
    }

    g_free(message);
    return TRUE;
}


static gboolean
http_cb_read(gpointer data, gint fd, b_input_condition cond)
{
    http_state_t *http_state = data;
    struct im_connection *ic = http_state->ic;
    GSocketConnection *connection = http_state->connection;

    GInputStream *istream = g_io_stream_get_input_stream(G_IO_STREAM(connection));
    GDataInputStream *gdi = g_data_input_stream_new(istream);
    g_data_input_stream_set_newline_type(gdi, G_DATA_STREAM_NEWLINE_TYPE_ANY);

    do {
        if (!http_read_line(http_state, ic, gdi)) {
            g_object_unref(gdi);
            return FALSE;
        }
    } while (g_buffered_input_stream_get_available(G_BUFFERED_INPUT_STREAM(gdi)));

    g_object_unref(gdi);

    return TRUE;
}

static gboolean
http_incoming_cb(GSocketService *service, GSocketConnection *connection, GObject *source_object, gpointer user_data)
{
    int fd;
    struct im_connection *ic = user_data;
    http_state_t *http_state;

    http_state = g_new0(http_state_t, 1);
    http_state->ic = ic;
    http_state->connection = connection;

    g_object_ref(connection);

    fd = g_socket_get_fd(g_socket_connection_get_socket(connection));
    b_input_add(fd, B_EV_IO_READ, http_cb_read, http_state);

    return FALSE;
}

static void
beessl_init(account_t *acct)
{
}

static void
beessl_login(account_t *acc)
{
    struct im_connection *ic = imcb_new(acc);
    GSocketService *service;

    service = g_socket_service_new();
    g_socket_listener_add_inet_port((GSocketListener *) service, atoi(acc->user), NULL, NULL);
    g_signal_connect(service, "incoming", G_CALLBACK(http_incoming_cb), ic);

    ic->proto_data = service;

    imcb_add_buddy(ic, BUDDY, NULL);
    imcb_buddy_status(ic, BUDDY, BEE_USER_ONLINE, NULL, NULL);
    imcb_connected(ic);
}

static void
beessl_logout(struct im_connection *ic)
{
    GSocketService *service = ic->proto_data;

    g_socket_service_stop(service);
    g_socket_listener_close((GSocketListener *) service);
    g_object_unref(service);
}

static int
beessl_buddy_msg(struct im_connection *ic, char *to, char *message, int flags)
{
}

G_MODULE_EXPORT void
init_plugin(void)
{
    struct prpl *dpp;

    static const struct prpl pp = {
        .name = "httpd",
        .init = beessl_init,
        .login = beessl_login,
        .logout = beessl_logout,
        .buddy_msg = beessl_buddy_msg,
        .handle_cmp = g_strcmp0,
        .options = PRPL_OPT_NO_PASSWORD,
    };

    dpp = g_memdup(&pp, sizeof pp);
    register_protocol(dpp);
}


#ifdef BITLBEE_ABI_VERSION_CODE
G_MODULE_EXPORT struct plugin_info *
init_plugin_info(void)
{
    static struct plugin_info info = {
        BITLBEE_ABI_VERSION_CODE,
        "httpd",
        "0.0.0",
        "httpd protocol plugin",
        "dequis <dx@dxzone.com.ar>",
        ""
    };

    return &info;
}
#endif
