// gcc -g -shared -fPIC $(pkg-config --cflags bitlbee) bitlbee_ssl.c -o bitlbee_ssl.so

#include <bitlbee.h>
#include <ssl_client.h>

static void
beessl_init(account_t *acct)
{
}

static gboolean
beessl_cb_read(gpointer data, gint fd, b_input_condition cond)
{
    struct im_connection *ic = data;
    void *conn = ic->proto_data;
    gchar buf[512];
    gchar *stringy;
    gssize size;

    if (conn == NULL) {
        return FALSE;
    }

    size = ssl_read(conn, buf, sizeof(buf));

    if (size == 0) {
        imcb_error(ic, "Disconnected");
        imc_logout(ic, FALSE);
        return FALSE;
    }

    stringy = g_strndup(buf, size);

    imcb_buddy_msg(ic, "peer", stringy, 0, 0);

    g_free(stringy);
    return TRUE;
}

static gboolean
beessl_cb_open(gpointer data, gint error, gpointer ssl, b_input_condition cond)
{
    struct im_connection *ic = data;
    void *conn = ic->proto_data;

    if ((ssl == NULL) || (error != SSL_OK)) {
        ic->proto_data = NULL;
        imcb_error(ic, "Error");
        return FALSE;
    }

    b_input_add(ssl_getfd(conn), B_EV_IO_READ, beessl_cb_read, ic);

    imcb_add_buddy(ic, "peer", NULL);
    imcb_buddy_status(ic, "peer", BEE_USER_ONLINE, NULL, NULL);
    imcb_connected(ic);
    return FALSE;
}

static void
beessl_login(account_t *acc)
{
    struct im_connection *ic = imcb_new(acc);

    imcb_log(ic, "Connecting");

    ic->proto_data = ssl_connect(acc->user, atoi(acc->pass), TRUE, beessl_cb_open, ic);

    if (ic->proto_data == NULL) {
        beessl_cb_open(ic, SSL_NOHANDSHAKE, NULL, 0);
    }
}

static void
beessl_logout(struct im_connection *ic)
{
    void *conn = ic->proto_data;

    ssl_disconnect(conn);

    ic->proto_data = NULL;
}

static int
beessl_buddy_msg(struct im_connection *ic, char *to, char *message, int flags)
{
    void *conn = ic->proto_data;

    ssl_write(conn, message, strlen(message));
    ssl_write(conn, "\n", 1);

    return 0;
}

G_MODULE_EXPORT void
init_plugin(void)
{
    struct prpl *dpp;

    static const struct prpl pp = {
        .name = "ssl",
        .init = beessl_init,
        .login = beessl_login,
        .logout = beessl_logout,
        .buddy_msg = beessl_buddy_msg,
        .handle_cmp = g_strcmp0,
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
        "ssl",
        "0.0.0",
        "ssl protocol plugin",
        "dequis <dx@dxzone.com.ar>",
        ""
    };

    return &info;
}
#endif