{application, mimicsocks,
 [{description, "just another TCP proxy"},
  {vsn, "1.0.0"},
  {modules, [mimicsocks_app, mimicsocks_cfg, mimicsocks_crypt, mimicsocks_inband_recv,
    mimicsocks_inband_send, mimicsocks_local, mimicsocks_local_agg,
    mimicsocks_mimic, mimicsocks_remote, mimicsocks_remote_agg, mimicsocks_remote_ho, 
    mimicsocks_remote_relay, mimicsocks_remote_socks, mimicsocks_sup, 
    mimicsocks_tcp_listener]},
  {registered, [mimicsocks_cfg]},
  {applications, [kernel, stdlib, sasl, crypto]},
  {mod, {mimicsocks_app,[]}},
  {env, [{log, []}]}
 ]}.