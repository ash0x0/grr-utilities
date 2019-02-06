#!/bin/sh
(nohup keycloak </dev/null >/dev/null 2>&1 &);
.  ~/.virtualenv/GRR/bin/activate;
(nohup grr_admin_ui </dev/null >/dev/null 2>&1 &);
(nohup grr_frontend </dev/null >/dev/null 2>&1 &);
(nohup grr_worker </dev/null >/dev/null 2>&1 &);
deactivate;
