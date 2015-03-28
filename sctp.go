package gosctp

/*
#cgo CFLAGS: -DINET -DINET6 -Wno-deprecated
#cgo LDFLAGS: -lusrsctp -lpthread
#cgo pkg-config: openssl

#include <stdlib.h>
#include <string.h>
#include <usrsctp.h>
#include <openssl/bio.h>

static int g_sctp_ref = 0;

typedef struct {
  struct socket *sock;
  BIO *ibio;
  BIO *obio;
  void *udata;
} sctp_transport;

extern void go_sctp_data_ready_cb(void *udata, void *data, size_t len);
static int sctp_data_ready_cb(void *udata, void *data, size_t len, uint8_t tos, uint8_t set_df) {
  go_sctp_data_ready_cb(udata, data, len);
  return 0;
}

extern void go_sctp_data_received_cb(void *udata, void *data, size_t len, int sid, int ppid);
extern void go_sctp_notification_received_cb(void *udata, void *data, size_t len);
static int sctp_data_received_cb(struct socket *sock, union sctp_sockstore addr, void *data,
                                 size_t len, struct sctp_rcvinfo recv_info, int flags, void *udata) {
  if (flags & MSG_NOTIFICATION)
    go_sctp_notification_received_cb(udata, data, len);
  else
    go_sctp_data_received_cb(udata, data, len, recv_info.rcv_sid, ntohl(recv_info.rcv_ppid));

  free(data);
  return 0;
}

static sctp_transport *new_sctp_transport(int port, void *udata) {
  if (udata == NULL)
    return NULL;

  sctp_transport *sctp = (sctp_transport *)calloc(1, sizeof *sctp);
  if (sctp == NULL)
    return NULL;
  sctp->udata = udata;

  if (g_sctp_ref == 0) {
    usrsctp_init(0, sctp_data_ready_cb, NULL);
    usrsctp_sysctl_set_sctp_ecn_enable(0);
  }
  g_sctp_ref++;

  usrsctp_register_address(udata);
  struct socket *s = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP,
                                    sctp_data_received_cb, NULL, 0, udata);
  if (s == NULL)
    goto trans_err;
  sctp->sock = s;

  BIO *bio = BIO_new(BIO_s_mem());
  if (bio == NULL)
    goto trans_err;
  BIO_set_mem_eof_return(bio, -1);
  sctp->ibio = bio;

  bio = BIO_new(BIO_s_mem());
  if (bio == NULL)
    goto trans_err;
  BIO_set_mem_eof_return(bio, -1);
  sctp->obio = bio;

  struct linger lopt;
  lopt.l_onoff = 1;
  lopt.l_linger = 0;
  usrsctp_setsockopt(s, SOL_SOCKET, SO_LINGER, &lopt, sizeof lopt);

  struct sctp_paddrparams addr_param;
  memset(&addr_param, 0, sizeof addr_param);
  addr_param.spp_flags = SPP_PMTUD_DISABLE;
  addr_param.spp_pathmtu = 1200;
  usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &addr_param, sizeof addr_param);

  struct sctp_assoc_value av;
  av.assoc_id = SCTP_ALL_ASSOC;
  av.assoc_value = 1;
  usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &av, sizeof av);

  uint32_t nodelay = 1;
  usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_NODELAY, &nodelay, sizeof nodelay);

  struct sctp_initmsg init_msg;
  memset(&init_msg, 0, sizeof init_msg);
  init_msg.sinit_num_ostreams = 1024;
  init_msg.sinit_max_instreams = 1023;
  usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_INITMSG, &init_msg, sizeof init_msg);

  struct sockaddr_conn sconn;
  memset(&sconn, 0, sizeof sconn);
  sconn.sconn_family = AF_CONN;
  sconn.sconn_port = htons(port);
  sconn.sconn_addr = (void *)sctp;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
  sconn.sconn_len = sizeof *sctp;
#endif
  if (usrsctp_bind(s, (struct sockaddr *)&sconn, sizeof sconn) < 0)
    goto trans_err;

  if (0) {
trans_err:
    usrsctp_finish();
    free(sctp);
    sctp = NULL;
  }

  return sctp;
}

static void release_usrsctp() {
  if (--g_sctp_ref <= 0) {
    g_sctp_ref = 0;
    usrsctp_finish();
  }
}

static ssize_t send_data(sctp_transport *sctp,
                         void *data, size_t len, uint16_t sid, uint32_t ppid)
{
  struct sctp_sndinfo info;
  memset(&info, 0, sizeof info);
  info.snd_sid = sid;
  info.snd_flags = SCTP_EOR;
  info.snd_ppid = htonl(ppid);
  return usrsctp_sendv(sctp->sock, data, len, NULL, 0,
                       &info, sizeof info, SCTP_SENDV_SNDINFO, 0);
}

static int connect_sctp(sctp_transport *sctp, int port, void *udata) {
  struct sockaddr_conn sconn;
  memset(&sconn, 0, sizeof sconn);
  sconn.sconn_family = AF_CONN;
  sconn.sconn_port = htons(port);
  sconn.sconn_addr = (void *)udata;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
  sconn.sconn_len = sizeof *udata;
#endif
  if (usrsctp_connect(sctp->sock, (struct sockaddr *)&sconn, sizeof sconn) < 0)
    return -1;

  return 0;
}

static int accept_sctp(sctp_transport *sctp, int port, void *udata) {
  struct sockaddr_conn sconn;
  memset(&sconn, 0, sizeof sconn);
  sconn.sconn_family = AF_CONN;
  sconn.sconn_port = htons(port);
  sconn.sconn_addr = (void *)udata;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
  sconn.sconn_len = sizeof *udata;
#endif
  usrsctp_listen(sctp->sock, 1);
  socklen_t len = sizeof sconn;
  struct socket *s = usrsctp_accept(sctp->sock, (struct sockaddr *)&sconn, &len);
  if (s) {
    struct socket *t = sctp->sock;
    sctp->sock = s;
    usrsctp_close(t);
    return 0;
  }

  return -1;
}
*/
import "C"

import (
  "errors"
  "unsafe"
  "sync"
)

type SctpTransport struct {
  sctp *C.sctp_transport
  port int
  mtx sync.Mutex
}

type callbackData struct {
  dataReadyCB, dataReceivedCB, notifReceivedCB interface{}
}

func NewTransport(port int) (*SctpTransport, error) {
  d := &callbackData{}
  sctp := C.new_sctp_transport(C.int(port), unsafe.Pointer(d))
  if sctp == nil {
    return nil, errors.New("failed to create SCTP transport")
  }
  return &SctpTransport{sctp: sctp, port: port}, nil
}

func (s *SctpTransport) Destroy() {
  C.usrsctp_close(s.sctp.sock)
  C.usrsctp_deregister_address(unsafe.Pointer(s.sctp))
  C.BIO_free_all(s.sctp.ibio)
  C.BIO_free_all(s.sctp.obio)
  C.free(unsafe.Pointer(s.sctp))
  C.release_usrsctp()
}

type DataReadyCB func(data []byte)

//export go_sctp_data_ready_cb
func go_sctp_data_ready_cb(udata, data unsafe.Pointer, length C.size_t) {
  d := (*callbackData)(udata)
  b := C.GoBytes(data, C.int(length))
  if d.dataReadyCB != nil {
    d.dataReadyCB.(DataReadyCB)(b)
  }
}

func (s *SctpTransport) SetDataReadyCB(cb DataReadyCB) {
  d := (*callbackData)(s.sctp.udata)
  d.dataReadyCB = cb
}

type DataReceivedCB func(data []byte, sid, ppid int)

//export go_sctp_data_received_cb
func go_sctp_data_received_cb(udata, data unsafe.Pointer, length C.size_t, sid, ppid C.int) {
  d := (*callbackData)(udata)
  b := C.GoBytes(data, C.int(length))
  if d.dataReceivedCB != nil {
    d.dataReceivedCB.(DataReceivedCB)(b, int(sid), int(ppid))
  }
}

func (s *SctpTransport) SetDataReceivedCB(cb DataReceivedCB) {
  d := (*callbackData)(s.sctp.udata)
  d.dataReceivedCB = cb
}

type NotificationReceivedCB func(data []byte)

//export go_sctp_notification_received_cb
func go_sctp_notification_received_cb(udata, data unsafe.Pointer, length C.size_t) {

}

func (s *SctpTransport) SetNotificationReceivedCB(cb NotificationReceivedCB) {
  d := (*callbackData)(s.sctp.udata)
  d.notifReceivedCB = cb
}

func (s *SctpTransport) Feed(data []byte) {
  s.mtx.Lock()
  defer s.mtx.Unlock()
  C.usrsctp_conninput(s.sctp.udata, unsafe.Pointer(&data[0]), C.size_t(len(data)), 0)
}

func (s *SctpTransport) Send(data []byte, sid, ppid int) (int, error) {
  s.mtx.Lock()
  defer s.mtx.Unlock()
  rv := C.send_data(s.sctp, unsafe.Pointer(&data[0]), C.size_t(len(data)), C.uint16_t(sid), C.uint32_t(ppid))
  if rv < 0 {
    return 0, errors.New("failed to send data")
  }
  return int(rv), nil
}

func (s *SctpTransport) Connect(port int) error {
  s.mtx.Lock()
  defer s.mtx.Unlock()
  rv := C.connect_sctp(s.sctp, C.int(port), s.sctp.udata)
  if rv < 0 {
    return errors.New("failed to connect SCTP transport")
  }
  return nil
}

func (s *SctpTransport) Accept() error {
  s.mtx.Lock()
  defer s.mtx.Unlock()
  rv := C.accept_sctp(s.sctp, C.int(s.port), s.sctp.udata)
  if rv < 0 {
    return errors.New("failed to accept SCTP transport")
  }
  return nil
}
