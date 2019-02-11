#!/bin/sh
.  ~/.virtualenv/GRR/bin/activate;
(nohup grr_admin_ui </dev/null >/dev/null 2>&1 &);
(nohup grr_frontend </dev/null >/dev/null 2>&1 &);
(nohup grr_worker </dev/null >/dev/null 2>&1 &);
(nohup grr_client </dev/null >/dev/null 2>&1 &);
deactivate;
