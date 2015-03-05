#ifndef __LIBCT_RPC_H__
#define __LIBCT_RPC_H__

struct _RpcResponse;
typedef struct _RpcResponse RpcResponse;
struct _RpcRequest;
typedef struct _RpcRequest RpcRequest;

extern int do_send_resp(int sk, RpcRequest *req, int err, RpcResponse *resp);
extern int send_resp(int sk, RpcRequest *req, int err);

extern int recv_req(int sk, RpcRequest **req, int **fds, int *nr_fds);

#endif
