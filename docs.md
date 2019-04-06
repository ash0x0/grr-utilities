____%BOF_______
Keepalive is not yet supported in Linux

First: client makes sure that it has already enrolled and instantiated a private key;
sends the first mesagethrough configuring the certificate and handshaking with the srrver 
(Line 65 at client/grr_response_client)
checks that there exists private keys in the client, if nothin is found then it initiates a 
private key and saves it
While the first message between client and server should be the startup message,
in practice it sends the foreman message because this happens on the comm threa
before starting the worker thread;
(    args_rdf_name : u'DataBlob') is sent first; nanny every 30 minutes
Note that requests and messages sent on comm thread shouldn't be blocking
 We must not queue messages from the comms thread with blocking=True
        # or we might deadlock. If the output queue is full, we can't accept
        # more work from the foreman anyways so it's ok to drop the message.

in_queue is where messages from server is queued in client
out_queue is the opposite

#TODO 
maybe I messed a bit with the clientstat message at startup; not sure if it used to 
get sent anyways
NOO 
the server keeps sending asking about the clientstats.. that was a rquest not
response

session_id=rdfvalue.FlowSessionID(flow_name="Foreman"),
#methods like that are gonna be removed; watch out

# TODO Remove this class in rdfvalues
class FlowSessionID(SessionID):
  pass

#return code 406 if clients needs enrollment	

receiving in the server side is preferred to happen in chunks rather tha
at a whole because of recv(n) issues with great n

every client has a queue for itts own messages and processing of them

____%EOF_______

____%BOF_______
Feb 24, 2019:
got the following errors which may guide us where to look for connections tracing and handling actions later on;
 File "/home/samanoudy/.virtualenv/GRR/bin/grr_client", line 11, in <module>
    load_entry_point('grr-response-client', 'console_scripts', 'grr_client')()
  File "/home/samanoudy/grr/grr/client/grr_response_client/distro_entry.py", line 19, in Client
    flags.StartMain(client.main)
  File "/home/samanoudy/grr/grr/core/grr_response_core/lib/flags.py", line 87, in StartMain
    app.run(main)
  File "/home/samanoudy/.virtualenv/GRR/lib/python2.7/site-packages/absl/app.py", line 300, in run
    _run_main(main, args)
  File "/home/samanoudy/.virtualenv/GRR/lib/python2.7/site-packages/absl/app.py", line 251, in _run_main
    sys.exit(main(argv))
  File "/home/samanoudy/grr/grr/client/grr_response_client/client.py", line 71, in main
    client.Run()
  File "/home/samanoudy/grr/grr/client/grr_response_client/comms.py", line 1258, in Run
    self.RunOnce()
  File "/home/samanoudy/grr/grr/client/grr_response_client/comms.py", line 1141, in RunOnce
    response = self.MakeRequest(payload_data)
  File "/home/samanoudy/grr/grr/client/grr_response_client/comms.py", line 1082, in MakeRequest
    headers={"Content-Type": "binary/octet-stream"})
  File "/home/samanoudy/grr/grr/client/grr_response_client/comms.py", line 236, in OpenServerEndpoint
    verify_cb=verify_cb,
  File "/home/samanoudy/grr/grr/client/grr_response_client/comms.py", line 313, in OpenURL
    proxies=proxydict,
  File "/home/samanoudy/grr/grr/client/grr_response_client/comms.py", line 387, in _RetryRequest
    result = requests.request(**request_args)
  File "/home/samanoudy/.virtualenv/GRR/lib/python2.7/site-packages/requests/api.py", line 60, in request
    return session.request(method=method, url=url, **kwargs)
  File "/home/samanoudy/.virtualenv/GRR/lib/python2.7/site-packages/requests/sessions.py", line 533, in request
    resp = self.send(prep, **send_kwargs)
  File "/home/samanoudy/.virtualenv/GRR/lib/python2.7/site-packages/requests/sessions.py", line 646, in send
    r = adapter.send(request, **kwargs)
  File "/home/samanoudy/.virtualenv/GRR/lib/python2.7/site-packages/requests/adapters.py", line 449, in send
    timeout=timeout
  File "/home/samanoudy/.virtualenv/GRR/lib/python2.7/site-packages/urllib3/connectionpool.py", line 600, in urlopen
    chunked=chunked)
  File "/home/samanoudy/.virtualenv/GRR/lib/python2.7/site-packages/urllib3/connectionpool.py", line 377, in _make_request
    httplib_response = conn.getresponse(buffering=True)
  File "/usr/lib/python2.7/httplib.py", line 1121, in getresponse
    response.begin()
  File "/usr/lib/python2.7/httplib.py", line 438, in begin
    version, status, reason = self._read_status()
  File "/usr/lib/python2.7/httplib.py", line 394, in _read_status
    line = self.fp.readline(_MAXLINE + 1)
  File "/usr/lib/python2.7/socket.py", line 480, in readline
    data = self._sock.recv(self._rbufsize)


2. Actions Execute: almost all messages have none as their args because   self.message.args_rdf_name is Null

3. function run in actions will always be overriden by real plugins run..
we need a flow that has action creating flow :)

4. init in Metaclass registry has name,cls of every registery class which is checked by client when searching through actions; there u can now what type of rdfvalue was sent and what object was targeted and also base class; most of the cls are from core.lib but some are for client.actions as well..

4. flow registery is accessed through grr_fronetend
5. Single hook run was called by client..
6. output plugins are called by server upon start:
<class 'grr_response_server.output_plugin.OutputPlugin'>
<class 'grr_response_server.output_plugin.UnknownOutputPlugin'>
<class 'grr_response_server.output_plugins.bigquery_plugin.BigQueryOutputPlugin'>
<class 'grr_response_server.output_plugins.email_plugin.EmailOutputPlugin'>


7. Init metaclass in registery in server has the following cls:
<class 'grr_response_core.lib.registry.InitHook'>
<class 'grr_response_core.lib.rdfvalue.RDFValue'>
<class 'grr_response_core.lib.rdfvalue.RDFPrimitive'>
<class 'grr_response_core.lib.rdfvalue.RDFBytes'>
<class 'grr_response_core.lib.rdfvalue.RDFZippedBytes'>
<class 'grr_response_core.lib.rdfvalue.RDFString'>
<class 'grr_response_core.lib.rdfvalue.HashDigest'>
<class 'grr_response_core.lib.rdfvalue.RDFInteger'>
<class 'grr_response_core.lib.rdfvalue.RDFBool'>
<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>
<class 'grr_response_core.lib.rdfvalue.RDFDatetimeSeconds'>
<class 'grr_response_core.lib.rdfvalue.Duration'>
<class 'grr_response_core.lib.rdfvalue.ByteSize'>
<class 'grr_response_core.lib.rdfvalue.RDFURN'>
<class 'grr_response_core.lib.rdfvalue.Subject'>
<class 'grr_response_core.lib.rdfvalue.SessionID'>
<class 'grr_response_core.lib.rdfvalue.FlowSessionID'>
<class 'grr_response_core.lib.type_info.TypeInfoObject'>
<class 'grr_response_core.lib.type_info.RDFValueType'>
<class 'grr_response_core.lib.type_info.RDFStructDictType'>
<class 'grr_response_core.lib.type_info.Bool'>
<class 'grr_response_core.lib.type_info.List'>
<class 'grr_response_core.lib.type_info.String'>
<class 'grr_response_core.lib.type_info.Bytes'>
<class 'grr_response_core.lib.type_info.Integer'>
<class 'grr_response_core.lib.type_info.Float'>
<class 'grr_response_core.lib.type_info.Choice'>
<class 'grr_response_core.lib.type_info.MultiChoice'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoType'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoString'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoBinary'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoUnsignedInteger'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoSignedInteger'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoFixed32'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoFixed64'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoFixedU32'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoFloat'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoDouble'>
<class 'grr_response_core.lib.rdfvalues.structs.EnumNamedValue'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoEnum'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoBoolean'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoEmbedded'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoDynamicEmbedded'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoDynamicAnyValueEmbedded'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoList'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoRDFValue'>
<class 'grr_response_core.lib.rdfvalues.structs.RDFStruct'>
<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>
<class 'grr_response_core.lib.rdfvalues.structs.SemanticDescriptor'>
<class 'grr_response_core.lib.rdfvalues.structs.AnyValue'>
<class 'grr_response_server.access_control.AccessControlManager'>
<class 'grr_response_server.access_control.ACLToken'>
<class 'grr_response_core.lib.config_lib.ConfigFilter'>
<class 'grr_response_core.lib.config_lib.Literal'>
<class 'grr_response_core.lib.config_lib.Lower'>
<class 'grr_response_core.lib.config_lib.Upper'>
<class 'grr_response_core.lib.config_lib.Filename'>
<class 'grr_response_core.lib.config_lib.OptionalFile'>
<class 'grr_response_core.lib.config_lib.FixPathSeparator'>
<class 'grr_response_core.lib.config_lib.Base64'>
<class 'grr_response_core.lib.config_lib.Env'>
<class 'grr_response_core.lib.config_lib.Expand'>
<class 'grr_response_core.lib.config_lib.Flags'>
<class 'grr_response_core.lib.config_lib.Resource'>
<class 'grr_response_core.lib.config_lib.ModulePath'>
<class 'grr_response_core.lib.config_lib.GRRConfigParser'>
<class 'grr_response_core.lib.config_lib.ConfigFileParser'>
<class 'grr_response_core.lib.config_lib.YamlParser'>
<class 'grr_response_core.lib.rdfvalues.standard.RegularExpression'>
<class 'grr_response_core.lib.rdfvalues.standard.LiteralExpression'>
<class 'grr_response_core.lib.rdfvalues.standard.EmailAddress'>
<class 'grr_response_core.lib.rdfvalues.standard.DomainEmailAddress'>
<class 'grr_response_core.lib.rdfvalues.standard.AuthenticodeSignedData'>
<class 'grr_response_core.lib.rdfvalues.standard.PersistenceFile'>
<class 'grr_response_core.lib.rdfvalues.standard.URI'>
<class 'grr_response_core.lib.rdfvalues.crypto.Certificate'>
<class 'grr_response_core.lib.rdfvalues.crypto.RDFX509Cert'>
<class 'grr_response_core.lib.rdfvalues.crypto.CertificateSigningRequest'>
<class 'grr_response_core.lib.rdfvalues.crypto.RSAPublicKey'>
<class 'grr_response_core.lib.rdfvalues.crypto.RSAPrivateKey'>
<class 'grr_response_core.lib.rdfvalues.crypto.PEMPrivateKey'>
<class 'grr_response_core.lib.rdfvalues.crypto.PEMPublicKey'>
<class 'grr_response_core.lib.rdfvalues.crypto.Hash'>
<class 'grr_response_core.lib.rdfvalues.crypto.SignedBlob'>
<class 'grr_response_core.lib.rdfvalues.crypto.EncryptionKey'>
<class 'grr_response_core.lib.rdfvalues.crypto.AES128Key'>
<class 'grr_response_core.lib.rdfvalues.crypto.AutoGeneratedAES128Key'>
<class 'grr_response_core.lib.rdfvalues.crypto.SymmetricCipher'>
<class 'grr_response_core.lib.rdfvalues.crypto.Password'>
<class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>
<class 'grr_response_core.lib.rdfvalues.paths.GlobExpression'>
<class 'grr_response_core.lib.rdfvalues.protodict.EmbeddedRDFValue'>
<class 'grr_response_core.lib.rdfvalues.protodict.DataBlob'>
<class 'grr_response_core.lib.rdfvalues.protodict.KeyValue'>
<class 'grr_response_core.lib.rdfvalues.protodict.Dict'>
<class 'grr_response_core.lib.rdfvalues.protodict.AttributedDict'>
<class 'grr_response_core.lib.rdfvalues.protodict.BlobArray'>
<class 'grr_response_core.lib.rdfvalues.protodict.RDFValueArray'>
<class 'grr_response_core.lib.rdfvalues.client_action.EchoRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.ExecuteBinaryRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.ExecuteBinaryResponse'>
<class 'grr_response_core.lib.rdfvalues.client_action.ExecutePythonRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.ExecutePythonResponse'>
<class 'grr_response_core.lib.rdfvalues.client_action.ExecuteRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.CopyPathToFileRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.ExecuteResponse'>
<class 'grr_response_core.lib.rdfvalues.client_action.SendFileRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.Iterator'>
<class 'grr_response_core.lib.rdfvalues.client_action.ListDirRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.GetFileStatRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.FingerprintTuple'>
<class 'grr_response_core.lib.rdfvalues.client_action.FingerprintRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.FingerprintResponse'>
<class 'grr_response_core.lib.rdfvalues.client_action.WMIRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.StatFSRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.GetClientStatsRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.ListNetworkConnectionsArgs'>
<class 'grr_response_core.lib.rdfvalues.client_fs.Filesystem'>
<class 'grr_response_core.lib.rdfvalues.client_fs.Filesystems'>
<class 'grr_response_core.lib.rdfvalues.client_fs.FolderInformation'>
<class 'grr_response_core.lib.rdfvalues.client_fs.WindowsVolume'>
<class 'grr_response_core.lib.rdfvalues.client_fs.UnixVolume'>
<class 'grr_response_core.lib.rdfvalues.client_fs.Volume'>
<class 'grr_response_core.lib.rdfvalues.client_fs.DiskUsage'>
<class 'grr_response_core.lib.rdfvalues.client_fs.Volumes'>
<class 'grr_response_core.lib.rdfvalues.client_fs.StatMode'>
<class 'grr_response_core.lib.rdfvalues.client_fs.StatExtFlagsOsx'>
<class 'grr_response_core.lib.rdfvalues.client_fs.StatExtFlagsLinux'>
<class 'grr_response_core.lib.rdfvalues.client_fs.ExtAttr'>
<class 'grr_response_core.lib.rdfvalues.client_fs.StatEntry'>
<class 'grr_response_core.lib.rdfvalues.client_fs.FindSpec'>
<class 'grr_response_core.lib.rdfvalues.client_fs.BareGrepSpec'>
<class 'grr_response_core.lib.rdfvalues.client_fs.GrepSpec'>
<class 'grr_response_core.lib.rdfvalues.client_fs.BlobImageChunkDescriptor'>
<class 'grr_response_core.lib.rdfvalues.client_fs.BlobImageDescriptor'>
<class 'grr_response_core.lib.rdfvalues.client_network.NetworkEndpoint'>
<class 'grr_response_core.lib.rdfvalues.client_network.NetworkConnection'>
<class 'grr_response_core.lib.rdfvalues.client_network.Connections'>
<class 'grr_response_core.lib.rdfvalues.client_network.NetworkAddress'>
<class 'grr_response_core.lib.rdfvalues.client_network.DNSClientConfiguration'>
<class 'grr_response_core.lib.rdfvalues.client_network.MacAddress'>
<class 'grr_response_core.lib.rdfvalues.client_network.Interface'>
<class 'grr_response_core.lib.rdfvalues.client_network.Interfaces'>
<class 'grr_response_core.lib.rdfvalues.client.ClientURN'>
<class 'grr_response_core.lib.rdfvalues.client.PCIDevice'>
<class 'grr_response_core.lib.rdfvalues.client.PackageRepository'>
<class 'grr_response_core.lib.rdfvalues.client.ManagementAgent'>
<class 'grr_response_core.lib.rdfvalues.client.PwEntry'>
<class 'grr_response_core.lib.rdfvalues.client.Group'>
<class 'grr_response_core.lib.rdfvalues.client.User'>
<class 'grr_response_core.lib.rdfvalues.client.KnowledgeBaseUser'>
<class 'grr_response_core.lib.rdfvalues.client.KnowledgeBase'>
<class 'grr_response_core.lib.rdfvalues.client.HardwareInfo'>
<class 'grr_response_core.lib.rdfvalues.client.ClientInformation'>
<class 'grr_response_core.lib.rdfvalues.client.BufferReference'>
<class 'grr_response_core.lib.rdfvalues.client.Process'>
<class 'grr_response_core.lib.rdfvalues.client.SoftwarePackage'>
<class 'grr_response_core.lib.rdfvalues.client.SoftwarePackages'>
<class 'grr_response_core.lib.rdfvalues.client.LogMessage'>
<class 'grr_response_core.lib.rdfvalues.client.Uname'>
<class 'grr_response_core.lib.rdfvalues.client.StartupInfo'>
<class 'grr_response_core.lib.rdfvalues.client.WindowsServiceInformation'>
<class 'grr_response_core.lib.rdfvalues.client.OSXServiceInformation'>
<class 'grr_response_core.lib.rdfvalues.client.LinuxServiceInformation'>
<class 'grr_response_core.lib.rdfvalues.client.RunKey'>
<class 'grr_response_core.lib.rdfvalues.client.RunKeyEntry'>
<class 'grr_response_core.lib.rdfvalues.client.ClientCrash'>
<class 'grr_response_core.lib.rdfvalues.client.ClientSummary'>
<class 'grr_response_core.lib.rdfvalues.client.VersionString'>
<class 'grr_response_core.config.build.PathTypeInfo'>
<class 'grr_response_core.lib.rdfvalues.config.AdminUIClientWarningRule'>
<class 'grr_response_core.lib.rdfvalues.config.AdminUIClientWarningsConfigOption'>
<class 'grr_response_core.lib.rdfvalues.client_stats.CpuSeconds'>
<class 'grr_response_core.lib.rdfvalues.client_stats.CpuSample'>
<class 'grr_response_core.lib.rdfvalues.client_stats.IOSample'>
<class 'grr_response_core.lib.rdfvalues.client_stats.ClientStats'>
<class 'grr_response_core.lib.rdfvalues.client_stats.ClientResources'>
<class 'grr_response_core.lib.rdfvalues.flows.GrrMessage'>
<class 'grr_response_core.lib.rdfvalues.flows.GrrStatus'>
<class 'grr_response_core.lib.rdfvalues.flows.GrrNotification'>
<class 'grr_response_core.lib.rdfvalues.flows.FlowProcessingRequest'>
<class 'grr_response_core.lib.rdfvalues.flows.Notification'>
<class 'grr_response_core.lib.rdfvalues.flows.FlowNotification'>
<class 'grr_response_core.lib.rdfvalues.flows.NotificationList'>
<class 'grr_response_core.lib.rdfvalues.flows.PackedMessageList'>
<class 'grr_response_core.lib.rdfvalues.flows.MessageList'>
<class 'grr_response_core.lib.rdfvalues.flows.CipherProperties'>
<class 'grr_response_core.lib.rdfvalues.flows.CipherMetadata'>
<class 'grr_response_core.lib.rdfvalues.flows.FlowLog'>
<class 'grr_response_core.lib.rdfvalues.flows.HttpRequest'>
<class 'grr_response_core.lib.rdfvalues.flows.ClientCommunication'>
<class 'grr_response_core.lib.rdfvalues.flows.AccessToken'>
<class 'grr_response_core.lib.rdfvalues.stats.Distribution'>
<class 'grr_response_core.lib.rdfvalues.stats.MetricFieldDefinition'>
<class 'grr_response_core.lib.rdfvalues.stats.MetricMetadata'>
<class 'grr_response_core.lib.rdfvalues.stats.StatsHistogramBin'>
<class 'grr_response_core.lib.rdfvalues.stats.StatsHistogram'>
<class 'grr_response_core.lib.rdfvalues.stats.RunningStats'>
<class 'grr_response_core.lib.rdfvalues.stats.ClientResourcesStats'>
<class 'grr_response_core.lib.rdfvalues.stats.Sample'>
<class 'grr_response_core.lib.rdfvalues.stats.SampleFloat'>
<class 'grr_response_core.lib.rdfvalues.stats.Graph'>
<class 'grr_response_core.lib.rdfvalues.stats.GraphFloat'>
<class 'grr_response_core.lib.rdfvalues.stats.GraphSeries'>
<class 'grr_response_core.lib.rdfvalues.stats.ClientGraphSeries'>
<class 'grr_response_core.lib.rdfvalues.cloud.CloudMetadataRequest'>
<class 'grr_response_core.lib.rdfvalues.cloud.CloudMetadataRequests'>
<class 'grr_response_core.lib.rdfvalues.cloud.CloudMetadataResponse'>
<class 'grr_response_core.lib.rdfvalues.cloud.CloudMetadataResponses'>
<class 'grr_response_core.lib.rdfvalues.cloud.GoogleCloudInstance'>
<class 'grr_response_core.lib.rdfvalues.cloud.AmazonCloudInstance'>
<class 'grr_response_core.lib.rdfvalues.cloud.CloudInstance'>
<class 'grr_response_server.rdfvalues.objects.ClientLabel'>
<class 'grr_response_server.rdfvalues.objects.StringMapEntry'>
<class 'grr_response_server.rdfvalues.objects.ClientSnapshot'>
<class 'grr_response_server.rdfvalues.objects.ClientMetadata'>
<class 'grr_response_server.rdfvalues.objects.ClientFullInfo'>
<class 'grr_response_server.rdfvalues.objects.GRRUser'>
<class 'grr_response_server.rdfvalues.objects.ApprovalGrant'>
<class 'grr_response_server.rdfvalues.objects.ApprovalRequest'>
<class 'grr_response_server.rdfvalues.objects.HashID'>
<class 'grr_response_server.rdfvalues.objects.PathID'>
<class 'grr_response_server.rdfvalues.objects.PathInfo'>
<class 'grr_response_server.rdfvalues.objects.ClientReference'>
<class 'grr_response_server.rdfvalues.objects.HuntReference'>
<class 'grr_response_server.rdfvalues.objects.CronJobReference'>
<class 'grr_response_server.rdfvalues.objects.FlowReference'>
<class 'grr_response_server.rdfvalues.objects.VfsFileReference'>
<class 'grr_response_server.rdfvalues.objects.ApprovalRequestReference'>
<class 'grr_response_server.rdfvalues.objects.ObjectReference'>
<class 'grr_response_server.rdfvalues.objects.UserNotification'>
<class 'grr_response_server.rdfvalues.objects.MessageHandlerRequest'>
<class 'grr_response_server.rdfvalues.objects.SHA256HashID'>
<class 'grr_response_server.rdfvalues.objects.BlobID'>
<class 'grr_response_server.rdfvalues.objects.ClientPathID'>
<class 'grr_response_server.rdfvalues.objects.BlobReference'>
<class 'grr_response_server.rdfvalues.objects.BlobReferences'>
<class 'grr_response_server.rdfvalues.objects.SerializedValueOfUnrecognizedType'>
<class 'grr_response_server.rdfvalues.objects.APIAuditEntry'>
<class 'grr_response_server.rdfvalues.objects.SignedBinaryID'>
<class 'grr_response_core.lib.rdfvalues.artifacts.ArtifactSource'>
<class 'grr_response_core.lib.rdfvalues.artifacts.ArtifactName'>
<class 'grr_response_core.lib.rdfvalues.artifacts.Artifact'>
<class 'grr_response_core.lib.rdfvalues.artifacts.ArtifactProcessorDescriptor'>
<class 'grr_response_core.lib.rdfvalues.artifacts.ArtifactDescriptor'>
<class 'grr_response_core.lib.rdfvalues.artifacts.ExpandedSource'>
<class 'grr_response_core.lib.rdfvalues.artifacts.ExpandedArtifact'>
<class 'grr_response_core.lib.rdfvalues.artifacts.ArtifactCollectorFlowArgs'>
<class 'grr_response_core.lib.rdfvalues.artifacts.ClientArtifactCollectorArgs'>
<class 'grr_response_core.lib.rdfvalues.artifacts.ClientActionResult'>
<class 'grr_response_core.lib.rdfvalues.artifacts.CollectedArtifact'>
<class 'grr_response_core.lib.rdfvalues.artifacts.ClientArtifactCollectorResult'>
<class 'grr_response_server.foreman_rules.ForemanClientRuleBase'>
<class 'grr_response_server.foreman_rules.ForemanOsClientRule'>
<class 'grr_response_server.foreman_rules.ForemanLabelClientRule'>
<class 'grr_response_server.foreman_rules.ForemanRegexClientRule'>
<class 'grr_response_server.foreman_rules.ForemanIntegerClientRule'>
<class 'grr_response_server.foreman_rules.ForemanRuleAction'>
<class 'grr_response_server.foreman_rules.ForemanClientRule'>
<class 'grr_response_server.foreman_rules.ForemanClientRuleSet'>
<class 'grr_response_server.foreman_rules.ForemanRule'>
<class 'grr_response_server.foreman_rules.ForemanCondition'>
<class 'grr_response_server.foreman_rules.ForemanRules'>
<class 'grr_response_server.rdfvalues.flow_runner.RequestState'>
<class 'grr_response_server.rdfvalues.flow_runner.FlowRunnerArgs'>
<class 'grr_response_server.rdfvalues.flow_runner.OutputPluginState'>
<class 'grr_response_server.rdfvalues.flow_runner.FlowContext'>
<class 'grr_response_server.rdfvalues.output_plugin.OutputPluginDescriptor'>
<class 'grr_response_server.rdfvalues.hunts.HuntNotification'>
<class 'grr_response_server.rdfvalues.hunts.HuntContext'>
<class 'grr_response_server.rdfvalues.hunts.FlowLikeObjectReference'>
<class 'grr_response_server.rdfvalues.hunts.HuntRunnerArgs'>
<class 'grr_response_server.rdfvalues.hunts.HuntError'>
<class 'grr_response_server.rdfvalues.hunts.GenericHuntArgs'>
<class 'grr_response_server.rdfvalues.hunts.CreateGenericHuntFlowArgs'>
<class 'grr_response_server.rdfvalues.cronjobs.CronJobRunStatus'>
<class 'grr_response_server.rdfvalues.cronjobs.CreateCronJobFlowArgs'>
<class 'grr_response_server.rdfvalues.cronjobs.SystemCronAction'>
<class 'grr_response_server.rdfvalues.cronjobs.HuntCronAction'>
<class 'grr_response_server.rdfvalues.cronjobs.CronJobAction'>
<class 'grr_response_server.rdfvalues.cronjobs.CronJob'>
<class 'grr_response_server.rdfvalues.cronjobs.CronJobRun'>
<class 'grr_response_server.rdfvalues.cronjobs.CreateCronJobArgs'>
<class 'grr_response_server.output_plugin.OutputPluginBatchProcessingStatus'>
<class 'grr_response_server.output_plugin.OutputPlugin'>
<class 'grr_response_server.output_plugin.UnknownOutputPlugin'>
<class 'grr_response_server.rdfvalues.flow_objects.PendingFlowTermination'>
<class 'grr_response_server.rdfvalues.flow_objects.FlowRequest'>
<class 'grr_response_server.rdfvalues.flow_objects.FlowResponse'>
<class 'grr_response_server.rdfvalues.flow_objects.FlowIterator'>
<class 'grr_response_server.rdfvalues.flow_objects.FlowStatus'>
<class 'grr_response_server.rdfvalues.flow_objects.FlowResult'>
<class 'grr_response_server.rdfvalues.flow_objects.FlowLogEntry'>
<class 'grr_response_server.rdfvalues.flow_objects.FlowOutputPluginLogEntry'>
<class 'grr_response_server.rdfvalues.flow_objects.Flow'>
<class 'grr_response_server.rdfvalues.hunt_objects.HuntArgumentsStandard'>
<class 'grr_response_server.rdfvalues.hunt_objects.VariableHuntFlowGroup'>
<class 'grr_response_server.rdfvalues.hunt_objects.HuntArgumentsVariable'>
<class 'grr_response_server.rdfvalues.hunt_objects.HuntArguments'>
<class 'grr_response_server.rdfvalues.hunt_objects.Hunt'>
<class 'grr_response_server.data_store.DataStore'>
<class 'grr_response_server.data_store.DataStoreInit'>
<class 'grr_response_server.rdfvalues.aff4.AFF4ObjectLabel'>
<class 'grr_response_server.rdfvalues.aff4.AFF4ObjectLabelsList'>
<class 'grr_response_server.aff4.AFF4Attribute'>
<class 'grr_response_server.aff4.AFF4Object'>
<class 'grr_response_server.aff4.AFF4Volume'>
<class 'grr_response_server.aff4.AFF4Root'>
<class 'grr_response_server.aff4.AFF4Symlink'>
<class 'grr_response_server.aff4.AFF4Stream'>
<class 'grr_response_server.aff4.AFF4MemoryStreamBase'>
<class 'grr_response_server.aff4.AFF4MemoryStream'>
<class 'grr_response_server.aff4.AFF4UnversionedMemoryStream'>
<class 'grr_response_server.aff4.AFF4ImageBase'>
<class 'grr_response_server.aff4.AFF4Image'>
<class 'grr_response_server.aff4.AFF4UnversionedImage'>
<class 'grr_response_server.aff4.AFF4InitHook'>
<class 'grr_response_core.lib.rdfvalues.nsrl.NSRLInformation'>
<class 'grr_response_core.lib.rdfvalues.events.AuditEvent'>
<class 'grr_response_server.events.EventListener'>
<class 'grr_response_core.lib.rdfvalues.chipsec_types.DumpFlashImageRequest'>
<class 'grr_response_core.lib.rdfvalues.chipsec_types.DumpFlashImageResponse'>
<class 'grr_response_core.lib.rdfvalues.chipsec_types.ACPITableData'>
<class 'grr_response_core.lib.rdfvalues.chipsec_types.DumpACPITableRequest'>
<class 'grr_response_core.lib.rdfvalues.chipsec_types.DumpACPITableResponse'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderModificationTimeCondition'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderAccessTimeCondition'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderInodeChangeTimeCondition'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderSizeCondition'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderExtFlagsCondition'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderContentsRegexMatchCondition'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderContentsLiteralMatchCondition'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderCondition'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderStatActionOptions'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderHashActionOptions'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderDownloadActionOptions'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderAction'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderArgs'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderResult'>
<class 'grr_response_core.lib.rdfvalues.osquery.OsqueryArgs'>
<class 'grr_response_core.lib.rdfvalues.osquery.OsqueryColumn'>
<class 'grr_response_core.lib.rdfvalues.osquery.OsqueryHeader'>
<class 'grr_response_core.lib.rdfvalues.osquery.OsqueryRow'>
<class 'grr_response_core.lib.rdfvalues.osquery.OsqueryTable'>
<class 'grr_response_core.lib.rdfvalues.osquery.OsqueryResult'>
<class 'grr_response_core.lib.rdfvalues.plist.FilterString'>
<class 'grr_response_core.lib.rdfvalues.plist.PlistQuery'>
<class 'grr_response_core.lib.rdfvalues.plist.PlistBoolDictEntry'>
<class 'grr_response_core.lib.rdfvalues.plist.PlistStringDictEntry'>
<class 'grr_response_core.lib.rdfvalues.plist.PlistRequest'>
<class 'grr_response_core.lib.rdfvalues.plist.LaunchdStartCalendarIntervalEntry'>
<class 'grr_response_core.lib.rdfvalues.plist.LaunchdKeepAlive'>
<class 'grr_response_core.lib.rdfvalues.plist.LaunchdPlist'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraSignature'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessScanRequest'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessError'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraStringMatch'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraMatch'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessScanMatch'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessScanMiss'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessScanResponse'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessDumpArgs'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessDumpInformation'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessDumpResponse'>
<class 'grr_response_server.server_stubs.ClientActionStub'>
<class 'grr_response_server.server_stubs.ArtifactCollector'>
<class 'grr_response_server.server_stubs.GetInstallDate'>
<class 'grr_response_server.server_stubs.EnumerateInterfaces'>
<class 'grr_response_server.server_stubs.EnumerateFilesystems'>
<class 'grr_response_server.server_stubs.Uninstall'>
<class 'grr_response_server.server_stubs.UpdateAgent'>
<class 'grr_response_server.server_stubs.WmiQuery'>
<class 'grr_response_server.server_stubs.OSXEnumerateRunningServices'>
<class 'grr_response_server.server_stubs.EnumerateRunningServices'>
<class 'grr_response_server.server_stubs.EnumerateUsers'>
<class 'grr_response_server.server_stubs.Echo'>
<class 'grr_response_server.server_stubs.GetHostname'>
<class 'grr_response_server.server_stubs.GetPlatformInfo'>
<class 'grr_response_server.server_stubs.Kill'>
<class 'grr_response_server.server_stubs.Hang'>
<class 'grr_response_server.server_stubs.BusyHang'>
<class 'grr_response_server.server_stubs.Bloat'>
<class 'grr_response_server.server_stubs.GetConfiguration'>
<class 'grr_response_server.server_stubs.GetLibraryVersions'>
<class 'grr_response_server.server_stubs.UpdateConfiguration'>
<class 'grr_response_server.server_stubs.GetClientInfo'>
<class 'grr_response_server.server_stubs.GetClientStats'>
<class 'grr_response_server.server_stubs.GetClientStatsAuto'>
<class 'grr_response_server.server_stubs.SendStartupInfo'>
<class 'grr_response_server.server_stubs.SaveCert'>
<class 'grr_response_server.server_stubs.PlistQuery'>
<class 'grr_response_server.server_stubs.ReadBuffer'>
<class 'grr_response_server.server_stubs.TransferBuffer'>
<class 'grr_response_server.server_stubs.HashBuffer'>
<class 'grr_response_server.server_stubs.HashFile'>
<class 'grr_response_server.server_stubs.CopyPathToFile'>
<class 'grr_response_server.server_stubs.ListDirectory'>
<class 'grr_response_server.server_stubs.StatFile'>
<class 'grr_response_server.server_stubs.GetFileStat'>
<class 'grr_response_server.server_stubs.ExecuteCommand'>
<class 'grr_response_server.server_stubs.ExecuteBinaryCommand'>
<class 'grr_response_server.server_stubs.ExecutePython'>
<class 'grr_response_server.server_stubs.Segfault'>
<class 'grr_response_server.server_stubs.ListProcesses'>
<class 'grr_response_server.server_stubs.SendFile'>
<class 'grr_response_server.server_stubs.StatFS'>
<class 'grr_response_server.server_stubs.GetMemorySize'>
<class 'grr_response_server.server_stubs.DeleteGRRTempFiles'>
<class 'grr_response_server.server_stubs.CheckFreeGRRTempSpace'>
<class 'grr_response_server.server_stubs.Find'>
<class 'grr_response_server.server_stubs.Grep'>
<class 'grr_response_server.server_stubs.Netstat'>
<class 'grr_response_server.server_stubs.ListNetworkConnections'>
<class 'grr_response_server.server_stubs.GetCloudVMMetadata'>
<class 'grr_response_server.server_stubs.FileFinderOS'>
<class 'grr_response_server.server_stubs.FingerprintFile'>
<class 'grr_response_server.server_stubs.DumpFlashImage'>
<class 'grr_response_server.server_stubs.DumpACPITable'>
<class 'grr_response_server.server_stubs.YaraProcessScan'>
<class 'grr_response_server.server_stubs.YaraProcessDump'>
<class 'grr_response_server.server_stubs.Osquery'>
<class 'grr_response_server.sequential_collection.UpdaterStartHook'>
<class 'grr_response_server.aff4_objects.users.CryptedPassword'>
<class 'grr_response_server.aff4_objects.users.GUISettings'>
<class 'grr_response_server.aff4_objects.users.GRRUser'>
<class 'grr_response_server.flow.EmptyFlowArgs'>
<class 'grr_response_server.flow.FlowBase'>
<class 'grr_response_server.flow.GRRFlow'>
<class 'grr_response_server.flow.WellKnownFlow'>
<class 'grr_response_server.aff4_objects.standard.VFSDirectory'>
<class 'grr_response_server.aff4_objects.standard.HashList'>
<class 'grr_response_server.aff4_objects.standard.AFF4SparseImage'>
<class 'grr_response_server.aff4_objects.standard.LabelSet'>
<class 'grr_response_server.aff4_objects.aff4_grr.SpaceSeparatedStringArray'>
<class 'grr_response_server.aff4_objects.aff4_grr.VFSGRRClient'>
<class 'grr_response_server.aff4_objects.aff4_grr.UpdateVFSFileArgs'>
<class 'grr_response_server.aff4_objects.aff4_grr.UpdateVFSFile'>
<class 'grr_response_server.aff4_objects.aff4_grr.VFSFile'>
<class 'grr_response_server.aff4_objects.aff4_grr.VFSMemoryFile'>
<class 'grr_response_server.aff4_objects.aff4_grr.GRRForeman'>
<class 'grr_response_server.aff4_objects.aff4_grr.GRRAFF4Init'>
<class 'grr_response_server.aff4_objects.aff4_grr.VFSFileSymlink'>
<class 'grr_response_server.aff4_objects.aff4_grr.VFSBlobImage'>
<class 'grr_response_server.aff4_objects.aff4_grr.TempKnowledgeBase'>
<class 'grr_response_server.aff4_objects.filestore.FileStore'>
<class 'grr_response_server.aff4_objects.filestore.FileStoreImage'>
<class 'grr_response_server.aff4_objects.filestore.FileStoreHash'>
<class 'grr_response_server.aff4_objects.filestore.HashFileStore'>
<class 'grr_response_server.aff4_objects.filestore.NSRLFile'>
<class 'grr_response_server.aff4_objects.filestore.NSRLFileStore'>
<class 'grr_response_server.aff4_objects.filestore.FileStoreInit'>
<class 'grr_response_core.lib.rdfvalues.cronjobs.CronTabEntry'>
<class 'grr_response_core.lib.rdfvalues.cronjobs.CronTabFile'>
<class 'grr_response_core.lib.parser.Parser'>
<class 'grr_response_core.lib.parser.CommandParser'>
<class 'grr_response_core.lib.parser.FileParser'>
<class 'grr_response_core.lib.parser.FileMultiParser'>
<class 'grr_response_core.lib.parser.WMIQueryParser'>
<class 'grr_response_core.lib.parser.RegistryValueParser'>
<class 'grr_response_core.lib.parser.RegistryParser'>
<class 'grr_response_core.lib.parser.RegistryMultiParser'>
<class 'grr_response_core.lib.parser.GrepParser'>
<class 'grr_response_core.lib.parser.ArtifactFilesParser'>
<class 'grr_response_core.lib.parser.ArtifactFilesMultiParser'>
<class 'grr_response_core.lib.rdfvalues.anomaly.Anomaly'>
<class 'grr_response_core.lib.rdfvalues.config_file.LogTarget'>
<class 'grr_response_core.lib.rdfvalues.config_file.LogConfig'>
<class 'grr_response_core.lib.rdfvalues.config_file.NfsClient'>
<class 'grr_response_core.lib.rdfvalues.config_file.NfsExport'>
<class 'grr_response_core.lib.rdfvalues.config_file.SshdMatchBlock'>
<class 'grr_response_core.lib.rdfvalues.config_file.SshdConfig'>
<class 'grr_response_core.lib.rdfvalues.config_file.NtpConfig'>
<class 'grr_response_core.lib.rdfvalues.config_file.PamConfigEntry'>
<class 'grr_response_core.lib.rdfvalues.config_file.PamConfig'>
<class 'grr_response_core.lib.rdfvalues.config_file.SudoersAlias'>
<class 'grr_response_core.lib.rdfvalues.config_file.SudoersDefault'>
<class 'grr_response_core.lib.rdfvalues.config_file.SudoersEntry'>
<class 'grr_response_core.lib.rdfvalues.config_file.SudoersConfig'>
<class 'grr_response_core.lib.parsers.config_file.NfsExportsParser'>
<class 'grr_response_core.lib.parsers.config_file.SshdConfigParser'>
<class 'grr_response_core.lib.parsers.config_file.SshdConfigCmdParser'>
<class 'grr_response_core.lib.parsers.config_file.MtabParser'>
<class 'grr_response_core.lib.parsers.config_file.MountCmdParser'>
<class 'grr_response_core.lib.parsers.config_file.RsyslogParser'>
<class 'grr_response_core.lib.parsers.config_file.PackageSourceParser'>
<class 'grr_response_core.lib.parsers.config_file.APTPackageSourceParser'>
<class 'grr_response_core.lib.parsers.config_file.YumPackageSourceParser'>
<class 'grr_response_core.lib.parsers.config_file.CronAtAllowDenyParser'>
<class 'grr_response_core.lib.parsers.config_file.NtpdParser'>
<class 'grr_response_core.lib.parsers.config_file.SudoersParser'>
<class 'grr_response_core.lib.parsers.cron_file_parser.CronTabParser'>
<class 'grr_response_core.lib.rdfvalues.webhistory.BrowserHistoryItem'>
<class 'grr_response_core.lib.parsers.ie_history.IEHistoryParser'>
<class 'grr_response_core.lib.parsers.linux_cmd_parser.YumListCmdParser'>
<class 'grr_response_core.lib.parsers.linux_cmd_parser.YumRepolistCmdParser'>
<class 'grr_response_core.lib.parsers.linux_cmd_parser.RpmCmdParser'>
<class 'grr_response_core.lib.parsers.linux_cmd_parser.DpkgCmdParser'>
<class 'grr_response_core.lib.parsers.linux_cmd_parser.DmidecodeCmdParser'>
<class 'grr_response_core.lib.parsers.linux_cmd_parser.PsCmdParser'>
<class 'grr_response_core.lib.parsers.linux_file_parser.PCIDevicesInfoParser'>
<class 'grr_response_core.lib.parsers.linux_file_parser.PasswdParser'>
<class 'grr_response_core.lib.parsers.linux_file_parser.PasswdBufferParser'>
<class 'grr_response_core.lib.parsers.linux_file_parser.LinuxWtmpParser'>
<class 'grr_response_core.lib.parsers.linux_file_parser.NetgroupParser'>
<class 'grr_response_core.lib.parsers.linux_file_parser.NetgroupBufferParser'>
<class 'grr_response_core.lib.parsers.linux_file_parser.LinuxBaseShadowParser'>
<class 'grr_response_core.lib.parsers.linux_file_parser.LinuxSystemGroupParser'>
<class 'grr_response_core.lib.parsers.linux_file_parser.LinuxSystemPasswdParser'>
<class 'grr_response_core.lib.parsers.linux_file_parser.PathParser'>
<class 'grr_response_core.lib.parsers.linux_pam_parser.PAMParser'>
<class 'grr_response_core.lib.parsers.linux_release_parser.LinuxReleaseParser'>
<class 'grr_response_core.lib.parsers.linux_service_parser.LinuxLSBInitParser'>
<class 'grr_response_core.lib.parsers.linux_service_parser.LinuxXinetdParser'>
<class 'grr_response_core.lib.parsers.linux_service_parser.LinuxSysVInitParser'>
<class 'grr_response_core.lib.parsers.linux_sysctl_parser.ProcSysParser'>
<class 'grr_response_core.lib.parsers.linux_sysctl_parser.SysctlCmdParser'>
<class 'grr_response_core.lib.parsers.osx_file_parser.OSXUsersParser'>
<class 'grr_response_core.lib.parsers.osx_file_parser.OSXSPHardwareDataTypeParser'>
<class 'grr_response_core.lib.parsers.osx_file_parser.OSXLaunchdPlistParser'>
<class 'grr_response_core.lib.parsers.osx_file_parser.OSXInstallHistoryPlistParser'>
<class 'grr_response_core.lib.parsers.osx_launchd.DarwinPersistenceMechanismsParser'>
<class 'grr_response_core.lib.parsers.windows_persistence.WindowsPersistenceMechanismsParser'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.CurrentControlSetKBParser'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.WinEnvironmentParser'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.WinSystemDriveParser'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.WinSystemRootParser'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.CodepageParser'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.ProfilesDirectoryEnvironmentVariable'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.AllUsersProfileEnvironmentVariable'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.WinUserSids'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.WinUserSpecialDirs'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.WinServicesParser'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.WinTimezoneParser'>
<class 'grr_response_core.lib.rdfvalues.wmi.WMIActiveScriptEventConsumer'>
<class 'grr_response_core.lib.rdfvalues.wmi.WMICommandLineEventConsumer'>
<class 'grr_response_core.lib.parsers.wmi_parser.WMIEventConsumerParser'>
<class 'grr_response_core.lib.parsers.wmi_parser.WMIActiveScriptEventConsumerParser'>
<class 'grr_response_core.lib.parsers.wmi_parser.WMICommandLineEventConsumerParser'>
<class 'grr_response_core.lib.parsers.wmi_parser.WMIInstalledSoftwareParser'>
<class 'grr_response_core.lib.parsers.wmi_parser.WMIHotfixesSoftwareParser'>
<class 'grr_response_core.lib.parsers.wmi_parser.WMIUserParser'>
<class 'grr_response_core.lib.parsers.wmi_parser.WMILogicalDisksParser'>
<class 'grr_response_core.lib.parsers.wmi_parser.WMIComputerSystemProductParser'>
<class 'grr_response_core.lib.parsers.wmi_parser.WMIInterfacesParser'>
<class 'grr_response_core.lib.parsers.linux_software_parser.DebianPackagesStatusParser'>
<class 'grr_response_server.aff4_objects.aff4_queue.Queue'>
<class 'grr_response_server.hunts.results.HuntResultNotification'>
<class 'grr_response_server.hunts.results.HuntResultQueue'>
<class 'grr_response_server.hunts.results.ResultQueueInitHook'>
<class 'grr_response_server.flow_base.FlowBase'>
<class 'grr_response_server.artifact.KnowledgeBaseInitializationArgs'>
<class 'abc.KnowledgeBaseInitializationFlow'>
<class 'abc.KnowledgeBaseInitializationFlow'>
<class 'grr_response_server.artifact.ArtifactLoader'>
<class 'grr_response_server.flows.general.artifact_fallbacks.ArtifactFallbackCollectorArgs'>
<class 'abc.SystemRootSystemDriveFallbackFlow'>
<class 'abc.SystemRootSystemDriveFallbackFlow'>
<class 'abc.WindowsAllUsersProfileFallbackFlow'>
<class 'abc.WindowsAllUsersProfileFallbackFlow'>
<class 'grr_response_server.flows.general.transfer.GetFileArgs'>
<class 'abc.GetFile'>
<class 'abc.GetFile'>
<class 'grr_response_server.flows.general.transfer.MultiGetFileArgs'>
<class 'abc.MultiGetFile'>
<class 'abc.MultiGetFile'>
<class 'grr_response_server.flows.general.transfer.LegacyFileStoreCreateFile'>
<class 'grr_response_server.flows.general.transfer.GetMBRArgs'>
<class 'abc.GetMBR'>
<class 'abc.GetMBR'>
<class 'grr_response_server.flows.general.transfer.TransferStore'>
<class 'abc.SendFile'>
<class 'abc.SendFile'>
<class 'grr_response_server.flows.general.filesystem.ListDirectoryArgs'>
<class 'abc.ListDirectory'>
<class 'abc.ListDirectory'>
<class 'grr_response_server.flows.general.filesystem.RecursiveListDirectoryArgs'>
<class 'abc.RecursiveListDirectory'>
<class 'abc.RecursiveListDirectory'>
<class 'grr_response_server.flows.general.filesystem.UpdateSparseImageChunksArgs'>
<class 'abc.UpdateSparseImageChunks'>
<class 'abc.UpdateSparseImageChunks'>
<class 'grr_response_server.flows.general.filesystem.FetchBufferForSparseImageArgs'>
<class 'abc.FetchBufferForSparseImage'>
<class 'abc.FetchBufferForSparseImage'>
<class 'grr_response_server.flows.general.filesystem.MakeNewAFF4SparseImageArgs'>
<class 'grr_response_server.flows.general.filesystem.MakeNewAFF4SparseImage'>
<class 'grr_response_server.flows.general.filesystem.GlobArgs'>
<class 'abc.Glob'>
<class 'abc.Glob'>
<class 'grr_response_server.flows.general.filesystem.DiskVolumeInfoArgs'>
<class 'abc.DiskVolumeInfo'>
<class 'abc.DiskVolumeInfo'>
<class 'grr_response_server.flows.general.fingerprint.FingerprintFileArgs'>
<class 'grr_response_server.flows.general.fingerprint.FingerprintFileResult'>
<class 'abc.FingerprintFile'>
<class 'abc.FingerprintFile'>
<class 'abc.FileFinder'>
<class 'abc.FileFinder'>
<class 'abc.ClientFileFinder'>
<class 'abc.ClientFileFinder'>
<class 'abc.ArtifactCollectorFlow'>
<class 'abc.ArtifactCollectorFlow'>
<class 'grr_response_server.flows.general.collectors.ArtifactFilesDownloaderFlowArgs'>
<class 'grr_response_server.flows.general.collectors.ArtifactFilesDownloaderResult'>
<class 'abc.ArtifactFilesDownloaderFlow'>
<class 'abc.ArtifactFilesDownloaderFlow'>
<class 'abc.ClientArtifactCollector'>
<class 'abc.ClientArtifactCollector'>
<class 'grr_response_server.export.ExportOptions'>
<class 'grr_response_server.export.ExportedMetadata'>
<class 'grr_response_server.export.ExportedClient'>
<class 'grr_response_server.export.ExportedFile'>
<class 'grr_response_server.export.ExportedRegistryKey'>
<class 'grr_response_server.export.ExportedProcess'>
<class 'grr_response_server.export.ExportedNetworkConnection'>
<class 'grr_response_server.export.ExportedDNSClientConfiguration'>
<class 'grr_response_server.export.ExportedOpenFile'>
<class 'grr_response_server.export.ExportedNetworkInterface'>
<class 'grr_response_server.export.ExportedFileStoreHash'>
<class 'grr_response_server.export.ExportedAnomaly'>
<class 'grr_response_server.export.ExportedCheckResult'>
<class 'grr_response_server.export.ExportedMatch'>
<class 'grr_response_server.export.ExportedBytes'>
<class 'grr_response_server.export.ExportedString'>
<class 'grr_response_server.export.ExportedDictItem'>
<class 'grr_response_server.export.ExportedArtifactFilesDownloaderResult'>
<class 'grr_response_server.export.ExportedYaraProcessScanMatch'>
<class 'grr_response_server.export.ExportConverter'>
<class 'grr_response_server.export.AutoExportedProtoStruct'>
<class 'grr_response_server.export.DataAgnosticExportConverter'>
<class 'grr_response_server.export.StatEntryToExportedFileConverter'>
<class 'grr_response_server.export.StatEntryToExportedRegistryKeyConverter'>
<class 'grr_response_server.export.NetworkConnectionToExportedNetworkConnectionConverter'>
<class 'grr_response_server.export.ProcessToExportedProcessConverter'>
<class 'grr_response_server.export.ProcessToExportedNetworkConnectionConverter'>
<class 'grr_response_server.export.ProcessToExportedOpenFileConverter'>
<class 'grr_response_server.export.InterfaceToExportedNetworkInterfaceConverter'>
<class 'grr_response_server.export.DNSClientConfigurationToExportedDNSClientConfiguration'>
<class 'grr_response_server.export.ClientSummaryToExportedNetworkInterfaceConverter'>
<class 'grr_response_server.export.ClientSummaryToExportedClientConverter'>
<class 'grr_response_server.export.BufferReferenceToExportedMatchConverter'>
<class 'grr_response_server.export.FileFinderResultConverter'>
<class 'grr_response_server.export.RDFURNConverter'>
<class 'grr_response_server.export.CollectionConverterBase'>
<class 'grr_response_server.export.GrrMessageCollectionConverter'>
<class 'grr_response_server.export.HuntResultCollectionConverter'>
<class 'grr_response_server.export.FlowResultCollectionConverter'>
<class 'grr_response_server.export.VFSFileToExportedFileConverter'>
<class 'grr_response_server.export.RDFBytesToExportedBytesConverter'>
<class 'grr_response_server.export.RDFStringToExportedStringConverter'>
<class 'grr_response_server.export.DictToExportedDictItemsConverter'>
<class 'grr_response_server.export.GrrMessageConverter'>
<class 'grr_response_server.export.FileStoreHashConverter'>
<class 'grr_response_server.export.CheckResultConverter'>
<class 'grr_response_server.export.ArtifactFilesDownloaderResultConverter'>
<class 'grr_response_server.export.YaraProcessScanResponseConverter'>
<class 'grr_response_server.ip_resolver.IPResolverBase'>
<class 'grr_response_server.ip_resolver.IPResolver'>
<class 'grr_response_server.ip_resolver.IPResolverInit'>
<class 'grr_response_server.master.DefaultMasterWatcher'>
<class 'grr_response_server.master.MasterInit'>
<class 'grr_response_server.output_plugins.bigquery_plugin.BigQueryOutputPluginArgs'>
<class 'grr_response_server.output_plugins.bigquery_plugin.BigQueryOutputPlugin'>
<class 'grr_response_server.instant_output_plugin.InstantOutputPlugin'>
<class 'grr_response_server.instant_output_plugin.InstantOutputPluginWithExportConversion'>
<class 'grr_response_server.output_plugins.csv_plugin.CSVInstantOutputPlugin'>
<class 'grr_response_server.email_alerts.EmailAlerterBase'>
<class 'grr_response_server.email_alerts.SMTPEmailAlerter'>
<class 'grr_response_server.email_alerts.EmailAlerterInit'>
<class 'grr_response_server.output_plugins.email_plugin.EmailOutputPluginArgs'>
<class 'grr_response_server.output_plugins.email_plugin.EmailOutputPlugin'>
<class 'grr_response_server.output_plugins.sqlite_plugin.SqliteInstantOutputPlugin'>
<class 'grr_response_server.output_plugins.yaml_plugin.YamlInstantOutputPluginWithExportConversion'>
<class 'grr_response_server.stats_server.StatsServerInit'>
<class 'grr_response_server.aff4_objects.collects.GRRSignedBlob'>
<class 'grr_response_server.cronjobs.CronJobBase'>
<class 'grr_response_server.cronjobs.SystemCronJobBase'>
<class 'grr_response_server.aff4_objects.cronjobs.SystemCronFlow'>
<class 'grr_response_server.aff4_objects.cronjobs.StatefulSystemCronFlow'>
<class 'grr_response_server.aff4_objects.cronjobs.CronJob'>
<class 'grr_response_server.aff4_objects.cronjobs.CronHook'>
<class 'grr_response_server.authorization.groups.GroupAccessManager'>
<class 'grr_response_server.authorization.groups.NoGroupAccess'>
<class 'grr_response_server.authorization.client_approval_auth.ClientApprovalAuthorization'>
<class 'grr_response_server.authorization.client_approval_auth.ClientApprovalAuthorizationInit'>
<class 'grr_response_server.aff4_objects.security.Approval'>
<class 'grr_response_server.aff4_objects.security.ApprovalWithApproversAndReason'>
<class 'grr_response_server.aff4_objects.security.ClientApproval'>
<class 'grr_response_server.aff4_objects.security.HuntApproval'>
<class 'grr_response_server.aff4_objects.security.CronJobApproval'>
<class 'grr_response_server.aff4_objects.stats.ClientStats'>
<class 'grr_response_server.aff4_objects.stats.ClientFleetStats'>
<class 'grr_response_server.aff4_objects.user_managers.FullAccessControlManager'>
<class 'grr_response_server.data_stores.fake_data_store.FakeDataStore'>
<class 'grr_response_server.data_stores.mysql_advanced_data_store.MySQLAdvancedDataStore'>
<class 'grr_response_server.keyword_index.AFF4KeywordIndex'>
<class 'grr_response_server.client_index.AFF4ClientIndex'>
<class 'grr_response_server.hunts.implementation.HuntResultsMetadata'>
<class 'grr_response_server.hunts.implementation.GRRHunt'>
<class 'grr_response_server.flows.cron.data_retention.CleanHunts'>
<class 'grr_response_server.flows.cron.data_retention.CleanHuntsCronJob'>
<class 'grr_response_server.flows.cron.data_retention.CleanCronJobs'>
<class 'grr_response_server.flows.cron.data_retention.CleanCronJobsCronJob'>
<class 'grr_response_server.flows.cron.data_retention.CleanInactiveClients'>
<class 'grr_response_server.flows.cron.data_retention.CleanInactiveClientsCronJob'>
<class 'grr_response_server.flows.general.discovery.InterrogateArgs'>
<class 'abc.Interrogate'>
<class 'abc.Interrogate'>
<class 'grr_response_server.flows.general.discovery.EnrolmentInterrogateEvent'>
<class 'grr_response_server.hunts.standard.RunHunt'>
<class 'grr_response_server.hunts.standard.CreateGenericHuntFlow'>
<class 'grr_response_server.hunts.standard.CreateAndRunGenericHuntFlow'>
<class 'grr_response_server.hunts.standard.SampleHuntArgs'>
<class 'grr_response_server.hunts.standard.SampleHunt'>
<class 'grr_response_server.hunts.standard.GenericHunt'>
<class 'grr_response_server.hunts.standard.FlowStartRequest'>
<class 'grr_response_server.hunts.standard.VariableGenericHuntArgs'>
<class 'grr_response_server.hunts.standard.VariableGenericHunt'>
<class 'grr_response_server.flows.cron.system.AbstractClientStatsCronJob'>
<class 'grr_response_server.flows.cron.system.GRRVersionBreakDownCronJob'>
<class 'grr_response_server.flows.cron.system.OSBreakDownCronJob'>
<class 'grr_response_server.flows.cron.system.LastAccessStatsCronJob'>
<class 'grr_response_server.flows.cron.system.AbstractClientStatsCronFlow'>
<class 'grr_response_server.flows.cron.system.GRRVersionBreakDown'>
<class 'grr_response_server.flows.cron.system.OSBreakDown'>
<class 'grr_response_server.flows.cron.system.LastAccessStats'>
<class 'grr_response_server.flows.cron.system.InterrogateClientsCronFlow'>
<class 'grr_response_server.flows.cron.system.InterrogateClientsCronJob'>
<class 'grr_response_server.flows.cron.system.PurgeClientStats'>
<class 'grr_response_server.flows.cron.system.PurgeClientStatsCronJob'>
<class 'grr_response_server.flows.cron.system.UpdateFSLastPingTimestamps'>
<class 'grr_response_server.flows.general.administrative.ClientCrashHandler'>
<class 'abc.GetClientStats'>
<class 'abc.GetClientStats'>
<class 'grr_response_server.flows.general.administrative.GetClientStatsAuto'>
<class 'grr_response_server.flows.general.administrative.DeleteGRRTempFilesArgs'>
<class 'abc.DeleteGRRTempFiles'>
<class 'abc.DeleteGRRTempFiles'>
<class 'grr_response_server.flows.general.administrative.UninstallArgs'>
<class 'abc.Uninstall'>
<class 'abc.Uninstall'>
<class 'abc.Kill'>
<class 'abc.Kill'>
<class 'grr_response_server.flows.general.administrative.UpdateConfigurationArgs'>
<class 'abc.UpdateConfiguration'>
<class 'abc.UpdateConfiguration'>
<class 'grr_response_server.flows.general.administrative.ExecutePythonHackArgs'>
<class 'abc.ExecutePythonHack'>
<class 'abc.ExecutePythonHack'>
<class 'grr_response_server.flows.general.administrative.ExecuteCommandArgs'>
<class 'abc.ExecuteCommand'>
<class 'abc.ExecuteCommand'>
<class 'grr_response_server.flows.general.administrative.Foreman'>
<class 'grr_response_server.flows.general.administrative.OnlineNotificationArgs'>
<class 'abc.OnlineNotification'>
<class 'abc.OnlineNotification'>
<class 'grr_response_server.flows.general.administrative.UpdateClientArgs'>
<class 'abc.UpdateClient'>
<class 'abc.UpdateClient'>
<class 'grr_response_server.flows.general.administrative.NannyMessageHandlerFlow'>
<class 'grr_response_server.flows.general.administrative.ClientAlertHandlerFlow'>
<class 'grr_response_server.flows.general.administrative.ClientStartupHandlerFlow'>
<class 'grr_response_server.flows.general.administrative.KeepAliveArgs'>
<class 'abc.KeepAlive'>
<class 'abc.KeepAlive'>
<class 'grr_response_server.flows.general.administrative.LaunchBinaryArgs'>
<class 'abc.LaunchBinary'>
<class 'abc.LaunchBinary'>
<class 'grr_response_server.flows.general.audit.AuditEventListener'>
<class 'grr_response_server.flows.general.ca_enroller.CAEnrolerArgs'>
<class 'abc.CAEnroler'>
<class 'abc.CAEnroler'>
<class 'grr_response_server.flows.general.ca_enroller.Enroler'>
<class 'grr_response_server.check_lib.filters.Filter'>
<class 'grr_response_server.check_lib.filters.AttrFilter'>
<class 'grr_response_server.check_lib.filters.ObjectFilter'>
<class 'grr_response_server.check_lib.filters.ForEach'>
<class 'grr_response_server.check_lib.filters.ItemFilter'>
<class 'grr_response_server.check_lib.filters.StatFilter'>
<class 'grr_response_server.check_lib.filters.RDFFilter'>
<class 'grr_response_server.check_lib.triggers.Target'>
<class 'grr_response_server.check_lib.checks.Hint'>
<class 'grr_response_server.check_lib.checks.Filter'>
<class 'grr_response_server.check_lib.checks.Probe'>
<class 'grr_response_server.check_lib.checks.Method'>
<class 'grr_response_server.check_lib.checks.CheckResult'>
<class 'grr_response_server.check_lib.checks.CheckResults'>
<class 'grr_response_server.check_lib.checks.Check'>
<class 'grr_response_server.check_lib.checks.CheckLoader'>
<class 'grr_response_server.flows.general.checks.CheckFlowArgs'>
<class 'abc.CheckRunner'>
<class 'abc.CheckRunner'>
<class 'grr_response_server.flows.general.data_migration.ClientVfsMigrationFlow'>
<class 'grr_response_server.flows.general.filetypes.PlistValueFilterArgs'>
<class 'grr_response_server.flows.general.filetypes.PlistValueFilter'>
<class 'grr_response_server.flows.general.find.FindFilesArgs'>
<class 'abc.FindFiles'>
<class 'abc.FindFiles'>
<class 'grr_response_server.flows.general.hardware.DumpFlashImageArgs'>
<class 'abc.DumpFlashImage'>
<class 'abc.DumpFlashImage'>
<class 'grr_response_server.flows.general.hardware.DumpACPITableArgs'>
<class 'abc.DumpACPITable'>
<class 'abc.DumpACPITable'>
<class 'grr_response_server.flows.general.network.NetstatArgs'>
<class 'abc.Netstat'>
<class 'abc.Netstat'>
<class 'abc.OsqueryFlow'>
<class 'abc.OsqueryFlow'>
<class 'grr_response_server.flows.general.processes.ListProcessesArgs'>
<class 'abc.ListProcesses'>
<class 'abc.ListProcesses'>
<class 'grr_response_server.flows.general.registry.RegistryFinderCondition'>
<class 'grr_response_server.flows.general.registry.RegistryFinderArgs'>
<class 'abc.RegistryFinder'>
<class 'abc.RegistryFinder'>
<class 'abc.CollectRunKeyBinaries'>
<class 'abc.CollectRunKeyBinaries'>
<class 'grr_response_core.lib.parsers.chrome_history.ChromeHistoryParser'>
<class 'grr_response_core.lib.parsers.firefox3_history.FirefoxHistoryParser'>
<class 'grr_response_server.flows.general.webhistory.ChromeHistoryArgs'>
<class 'abc.ChromeHistory'>
<class 'abc.ChromeHistory'>
<class 'grr_response_server.flows.general.webhistory.FirefoxHistoryArgs'>
<class 'abc.FirefoxHistory'>
<class 'abc.FirefoxHistory'>
<class 'grr_response_server.flows.general.webhistory.CacheGrepArgs'>
<class 'abc.CacheGrep'>
<class 'abc.CacheGrep'>
<class 'grr_response_server.flows.general.windows_vsc.ListVolumeShadowCopies'>
<class 'abc.YaraProcessScan'>
<class 'abc.YaraProcessScan'>
<class 'abc.YaraDumpProcessMemory'>
<class 'abc.YaraDumpProcessMemory'>
<class 'abc.ProcessHuntResultCollectionsCronFlow'>
<class 'abc.ProcessHuntResultCollectionsCronJob'>


8. in client it not all of them are loaded:
<class 'grr_response_core.lib.registry.InitHook'>
<class 'grr_response_core.lib.rdfvalue.RDFValue'>
<class 'grr_response_core.lib.rdfvalue.RDFPrimitive'>
<class 'grr_response_core.lib.rdfvalue.RDFBytes'>
<class 'grr_response_core.lib.rdfvalue.RDFZippedBytes'>
<class 'grr_response_core.lib.rdfvalue.RDFString'>
<class 'grr_response_core.lib.rdfvalue.HashDigest'>
<class 'grr_response_core.lib.rdfvalue.RDFInteger'>
<class 'grr_response_core.lib.rdfvalue.RDFBool'>
<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>
<class 'grr_response_core.lib.rdfvalue.RDFDatetimeSeconds'>
<class 'grr_response_core.lib.rdfvalue.Duration'>
<class 'grr_response_core.lib.rdfvalue.ByteSize'>
<class 'grr_response_core.lib.rdfvalue.RDFURN'>
<class 'grr_response_core.lib.rdfvalue.Subject'>
<class 'grr_response_core.lib.rdfvalue.SessionID'>
<class 'grr_response_core.lib.rdfvalue.FlowSessionID'>
<class 'grr_response_core.lib.type_info.TypeInfoObject'>
<class 'grr_response_core.lib.type_info.RDFValueType'>
<class 'grr_response_core.lib.type_info.RDFStructDictType'>
<class 'grr_response_core.lib.type_info.Bool'>
<class 'grr_response_core.lib.type_info.List'>
<class 'grr_response_core.lib.type_info.String'>
<class 'grr_response_core.lib.type_info.Bytes'>
<class 'grr_response_core.lib.type_info.Integer'>
<class 'grr_response_core.lib.type_info.Float'>
<class 'grr_response_core.lib.type_info.Choice'>
<class 'grr_response_core.lib.type_info.MultiChoice'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoType'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoString'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoBinary'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoUnsignedInteger'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoSignedInteger'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoFixed32'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoFixed64'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoFixedU32'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoFloat'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoDouble'>
<class 'grr_response_core.lib.rdfvalues.structs.EnumNamedValue'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoEnum'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoBoolean'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoEmbedded'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoDynamicEmbedded'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoDynamicAnyValueEmbedded'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoList'>
<class 'grr_response_core.lib.rdfvalues.structs.ProtoRDFValue'>
<class 'grr_response_core.lib.rdfvalues.structs.RDFStruct'>
<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>
<class 'grr_response_core.lib.rdfvalues.structs.SemanticDescriptor'>
<class 'grr_response_core.lib.rdfvalues.structs.AnyValue'>
<class 'grr_response_core.lib.config_lib.ConfigFilter'>
<class 'grr_response_core.lib.config_lib.Literal'>
<class 'grr_response_core.lib.config_lib.Lower'>
<class 'grr_response_core.lib.config_lib.Upper'>
<class 'grr_response_core.lib.config_lib.Filename'>
<class 'grr_response_core.lib.config_lib.OptionalFile'>
<class 'grr_response_core.lib.config_lib.FixPathSeparator'>
<class 'grr_response_core.lib.config_lib.Base64'>
<class 'grr_response_core.lib.config_lib.Env'>
<class 'grr_response_core.lib.config_lib.Expand'>
<class 'grr_response_core.lib.config_lib.Flags'>
<class 'grr_response_core.lib.config_lib.Resource'>
<class 'grr_response_core.lib.config_lib.ModulePath'>
<class 'grr_response_core.lib.config_lib.GRRConfigParser'>
<class 'grr_response_core.lib.config_lib.ConfigFileParser'>
<class 'grr_response_core.lib.config_lib.YamlParser'>
<class 'grr_response_core.lib.rdfvalues.standard.RegularExpression'>
<class 'grr_response_core.lib.rdfvalues.standard.LiteralExpression'>
<class 'grr_response_core.lib.rdfvalues.standard.EmailAddress'>
<class 'grr_response_core.lib.rdfvalues.standard.DomainEmailAddress'>
<class 'grr_response_core.lib.rdfvalues.standard.AuthenticodeSignedData'>
<class 'grr_response_core.lib.rdfvalues.standard.PersistenceFile'>
<class 'grr_response_core.lib.rdfvalues.standard.URI'>
<class 'grr_response_core.lib.rdfvalues.crypto.Certificate'>
<class 'grr_response_core.lib.rdfvalues.crypto.RDFX509Cert'>
<class 'grr_response_core.lib.rdfvalues.crypto.CertificateSigningRequest'>
<class 'grr_response_core.lib.rdfvalues.crypto.RSAPublicKey'>
<class 'grr_response_core.lib.rdfvalues.crypto.RSAPrivateKey'>
<class 'grr_response_core.lib.rdfvalues.crypto.PEMPrivateKey'>
<class 'grr_response_core.lib.rdfvalues.crypto.PEMPublicKey'>
<class 'grr_response_core.lib.rdfvalues.crypto.Hash'>
<class 'grr_response_core.lib.rdfvalues.crypto.SignedBlob'>
<class 'grr_response_core.lib.rdfvalues.crypto.EncryptionKey'>
<class 'grr_response_core.lib.rdfvalues.crypto.AES128Key'>
<class 'grr_response_core.lib.rdfvalues.crypto.AutoGeneratedAES128Key'>
<class 'grr_response_core.lib.rdfvalues.crypto.SymmetricCipher'>
<class 'grr_response_core.lib.rdfvalues.crypto.Password'>
<class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>
<class 'grr_response_core.lib.rdfvalues.paths.GlobExpression'>
<class 'grr_response_core.lib.rdfvalues.protodict.EmbeddedRDFValue'>
<class 'grr_response_core.lib.rdfvalues.protodict.DataBlob'>
<class 'grr_response_core.lib.rdfvalues.protodict.KeyValue'>
<class 'grr_response_core.lib.rdfvalues.protodict.Dict'>
<class 'grr_response_core.lib.rdfvalues.protodict.AttributedDict'>
<class 'grr_response_core.lib.rdfvalues.protodict.BlobArray'>
<class 'grr_response_core.lib.rdfvalues.protodict.RDFValueArray'>
<class 'grr_response_core.lib.rdfvalues.client_action.EchoRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.ExecuteBinaryRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.ExecuteBinaryResponse'>
<class 'grr_response_core.lib.rdfvalues.client_action.ExecutePythonRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.ExecutePythonResponse'>
<class 'grr_response_core.lib.rdfvalues.client_action.ExecuteRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.CopyPathToFileRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.ExecuteResponse'>
<class 'grr_response_core.lib.rdfvalues.client_action.SendFileRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.Iterator'>
<class 'grr_response_core.lib.rdfvalues.client_action.ListDirRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.GetFileStatRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.FingerprintTuple'>
<class 'grr_response_core.lib.rdfvalues.client_action.FingerprintRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.FingerprintResponse'>
<class 'grr_response_core.lib.rdfvalues.client_action.WMIRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.StatFSRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.GetClientStatsRequest'>
<class 'grr_response_core.lib.rdfvalues.client_action.ListNetworkConnectionsArgs'>
<class 'grr_response_core.lib.rdfvalues.client_fs.Filesystem'>
<class 'grr_response_core.lib.rdfvalues.client_fs.Filesystems'>
<class 'grr_response_core.lib.rdfvalues.client_fs.FolderInformation'>
<class 'grr_response_core.lib.rdfvalues.client_fs.WindowsVolume'>
<class 'grr_response_core.lib.rdfvalues.client_fs.UnixVolume'>
<class 'grr_response_core.lib.rdfvalues.client_fs.Volume'>
<class 'grr_response_core.lib.rdfvalues.client_fs.DiskUsage'>
<class 'grr_response_core.lib.rdfvalues.client_fs.Volumes'>
<class 'grr_response_core.lib.rdfvalues.client_fs.StatMode'>
<class 'grr_response_core.lib.rdfvalues.client_fs.StatExtFlagsOsx'>
<class 'grr_response_core.lib.rdfvalues.client_fs.StatExtFlagsLinux'>
<class 'grr_response_core.lib.rdfvalues.client_fs.ExtAttr'>
<class 'grr_response_core.lib.rdfvalues.client_fs.StatEntry'>
<class 'grr_response_core.lib.rdfvalues.client_fs.FindSpec'>
<class 'grr_response_core.lib.rdfvalues.client_fs.BareGrepSpec'>
<class 'grr_response_core.lib.rdfvalues.client_fs.GrepSpec'>
<class 'grr_response_core.lib.rdfvalues.client_fs.BlobImageChunkDescriptor'>
<class 'grr_response_core.lib.rdfvalues.client_fs.BlobImageDescriptor'>
<class 'grr_response_core.config.build.PathTypeInfo'>
<class 'grr_response_core.lib.rdfvalues.config.AdminUIClientWarningRule'>
<class 'grr_response_core.lib.rdfvalues.config.AdminUIClientWarningsConfigOption'>
<class 'grr_response_core.lib.rdfvalues.client_network.NetworkEndpoint'>
<class 'grr_response_core.lib.rdfvalues.client_network.NetworkConnection'>
<class 'grr_response_core.lib.rdfvalues.client_network.Connections'>
<class 'grr_response_core.lib.rdfvalues.client_network.NetworkAddress'>
<class 'grr_response_core.lib.rdfvalues.client_network.DNSClientConfiguration'>
<class 'grr_response_core.lib.rdfvalues.client_network.MacAddress'>
<class 'grr_response_core.lib.rdfvalues.client_network.Interface'>
<class 'grr_response_core.lib.rdfvalues.client_network.Interfaces'>
<class 'grr_response_core.lib.rdfvalues.client.ClientURN'>
<class 'grr_response_core.lib.rdfvalues.client.PCIDevice'>
<class 'grr_response_core.lib.rdfvalues.client.PackageRepository'>
<class 'grr_response_core.lib.rdfvalues.client.ManagementAgent'>
<class 'grr_response_core.lib.rdfvalues.client.PwEntry'>
<class 'grr_response_core.lib.rdfvalues.client.Group'>
<class 'grr_response_core.lib.rdfvalues.client.User'>
<class 'grr_response_core.lib.rdfvalues.client.KnowledgeBaseUser'>
<class 'grr_response_core.lib.rdfvalues.client.KnowledgeBase'>
<class 'grr_response_core.lib.rdfvalues.client.HardwareInfo'>
<class 'grr_response_core.lib.rdfvalues.client.ClientInformation'>
<class 'grr_response_core.lib.rdfvalues.client.BufferReference'>
<class 'grr_response_core.lib.rdfvalues.client.Process'>
<class 'grr_response_core.lib.rdfvalues.client.SoftwarePackage'>
<class 'grr_response_core.lib.rdfvalues.client.SoftwarePackages'>
<class 'grr_response_core.lib.rdfvalues.client.LogMessage'>
<class 'grr_response_core.lib.rdfvalues.client.Uname'>
<class 'grr_response_core.lib.rdfvalues.client.StartupInfo'>
<class 'grr_response_core.lib.rdfvalues.client.WindowsServiceInformation'>
<class 'grr_response_core.lib.rdfvalues.client.OSXServiceInformation'>
<class 'grr_response_core.lib.rdfvalues.client.LinuxServiceInformation'>
<class 'grr_response_core.lib.rdfvalues.client.RunKey'>
<class 'grr_response_core.lib.rdfvalues.client.RunKeyEntry'>
<class 'grr_response_core.lib.rdfvalues.client.ClientCrash'>
<class 'grr_response_core.lib.rdfvalues.client.ClientSummary'>
<class 'grr_response_core.lib.rdfvalues.client.VersionString'>
<class 'grr_response_core.lib.rdfvalues.client_stats.CpuSeconds'>
<class 'grr_response_core.lib.rdfvalues.client_stats.CpuSample'>
<class 'grr_response_core.lib.rdfvalues.client_stats.IOSample'>
<class 'grr_response_core.lib.rdfvalues.client_stats.ClientStats'>
<class 'grr_response_core.lib.rdfvalues.client_stats.ClientResources'>
<class 'grr_response_core.lib.rdfvalues.flows.GrrMessage'>
<class 'grr_response_core.lib.rdfvalues.flows.GrrStatus'>
<class 'grr_response_core.lib.rdfvalues.flows.GrrNotification'>
<class 'grr_response_core.lib.rdfvalues.flows.FlowProcessingRequest'>
<class 'grr_response_core.lib.rdfvalues.flows.Notification'>
<class 'grr_response_core.lib.rdfvalues.flows.FlowNotification'>
<class 'grr_response_core.lib.rdfvalues.flows.NotificationList'>
<class 'grr_response_core.lib.rdfvalues.flows.PackedMessageList'>
<class 'grr_response_core.lib.rdfvalues.flows.MessageList'>
<class 'grr_response_core.lib.rdfvalues.flows.CipherProperties'>
<class 'grr_response_core.lib.rdfvalues.flows.CipherMetadata'>
<class 'grr_response_core.lib.rdfvalues.flows.FlowLog'>
<class 'grr_response_core.lib.rdfvalues.flows.HttpRequest'>
<class 'grr_response_core.lib.rdfvalues.flows.ClientCommunication'>
<class 'grr_response_core.lib.rdfvalues.flows.AccessToken'>
<class 'grr_response_client.actions.ActionPlugin'>
<class 'grr_response_client.actions.IteratedAction'>
<class 'grr_response_client.vfs.VFSHandler'>
<class 'grr_response_client.vfs.VFSInit'>
<class 'grr_response_client.vfs_handlers.files.File'>
<class 'grr_response_client.vfs_handlers.files.TempFile'>
<class 'grr_response_client.client_actions.tempfiles.DeleteGRRTempFiles'>
<class 'grr_response_client.client_actions.tempfiles.CheckFreeGRRTempSpace'>
<class 'grr_response_client.client_actions.admin.Echo'>
<class 'grr_response_client.client_actions.admin.GetHostname'>
<class 'grr_response_client.client_actions.admin.GetPlatformInfo'>
<class 'grr_response_client.client_actions.admin.Kill'>
<class 'grr_response_client.client_actions.admin.Hang'>
<class 'grr_response_client.client_actions.admin.BusyHang'>
<class 'grr_response_client.client_actions.admin.Bloat'>
<class 'grr_response_client.client_actions.admin.GetConfiguration'>
<class 'grr_response_client.client_actions.admin.GetLibraryVersions'>
<class 'grr_response_client.client_actions.admin.UpdateConfiguration'>
<class 'grr_response_client.client_actions.admin.GetClientInfo'>
<class 'grr_response_client.client_actions.admin.GetClientStats'>
<class 'grr_response_client.client_actions.admin.GetClientStatsAuto'>
<class 'grr_response_client.client_actions.admin.SendStartupInfo'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderModificationTimeCondition'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderAccessTimeCondition'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderInodeChangeTimeCondition'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderSizeCondition'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderExtFlagsCondition'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderContentsRegexMatchCondition'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderContentsLiteralMatchCondition'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderCondition'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderStatActionOptions'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderHashActionOptions'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderDownloadActionOptions'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderAction'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderArgs'>
<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderResult'>
<class 'grr_response_client.client_actions.file_finder.FileFinderOS'>
<class 'grr_response_client.client_actions.network.ListNetworkConnections'>
<class 'grr_response_client.client_actions.standard.ReadBuffer'>
<class 'grr_response_client.client_actions.standard.TransferBuffer'>
<class 'grr_response_client.client_actions.standard.HashBuffer'>
<class 'grr_response_client.client_actions.standard.HashFile'>
<class 'grr_response_client.client_actions.standard.CopyPathToFile'>
<class 'grr_response_client.client_actions.standard.ListDirectory'>
<class 'grr_response_client.client_actions.standard.GetFileStat'>
<class 'grr_response_client.client_actions.standard.ExecuteCommand'>
<class 'grr_response_client.client_actions.standard.ExecuteBinaryCommand'>
<class 'grr_response_client.client_actions.standard.ExecutePython'>
<class 'grr_response_client.client_actions.standard.Segfault'>
<class 'grr_response_client.client_actions.standard.ListProcesses'>
<class 'grr_response_client.client_actions.standard.SendFile'>
<class 'grr_response_client.client_actions.standard.StatFS'>
<class 'grr_response_client.client_actions.standard.GetMemorySize'>
<class 'grr_response_client.client_actions.linux.linux.EnumerateInterfaces'>
<class 'grr_response_client.client_actions.linux.linux.GetInstallDate'>
<class 'grr_response_client.client_actions.linux.linux.EnumerateUsers'>
<class 'grr_response_client.client_actions.linux.linux.EnumerateFilesystems'>
<class 'grr_response_client.client_actions.linux.linux.EnumerateRunningServices'>
<class 'grr_response_client.client_actions.linux.linux.Uninstall'>
<class 'grr_response_client.client_actions.linux.linux.UpdateAgent'>
<class 'grr_response_core.lib.rdfvalues.chipsec_types.DumpFlashImageRequest'>
<class 'grr_response_core.lib.rdfvalues.chipsec_types.DumpFlashImageResponse'>
<class 'grr_response_core.lib.rdfvalues.chipsec_types.ACPITableData'>
<class 'grr_response_core.lib.rdfvalues.chipsec_types.DumpACPITableRequest'>
<class 'grr_response_core.lib.rdfvalues.chipsec_types.DumpACPITableResponse'>
<class 'grr_response_client.components.chipsec_support.actions.grr_chipsec.DumpFlashImage'>
<class 'grr_response_client.components.chipsec_support.actions.grr_chipsec.DumpACPITable'>
<class 'grr_response_core.lib.rdfvalues.cronjobs.CronTabEntry'>
<class 'grr_response_core.lib.rdfvalues.cronjobs.CronTabFile'>
<class 'grr_response_core.lib.parser.Parser'>
<class 'grr_response_core.lib.parser.CommandParser'>
<class 'grr_response_core.lib.parser.FileParser'>
<class 'grr_response_core.lib.parser.FileMultiParser'>
<class 'grr_response_core.lib.parser.WMIQueryParser'>
<class 'grr_response_core.lib.parser.RegistryValueParser'>
<class 'grr_response_core.lib.parser.RegistryParser'>
<class 'grr_response_core.lib.parser.RegistryMultiParser'>
<class 'grr_response_core.lib.parser.GrepParser'>
<class 'grr_response_core.lib.parser.ArtifactFilesParser'>
<class 'grr_response_core.lib.parser.ArtifactFilesMultiParser'>
<class 'grr_response_core.lib.rdfvalues.anomaly.Anomaly'>
<class 'grr_response_core.lib.rdfvalues.config_file.LogTarget'>
<class 'grr_response_core.lib.rdfvalues.config_file.LogConfig'>
<class 'grr_response_core.lib.rdfvalues.config_file.NfsClient'>
<class 'grr_response_core.lib.rdfvalues.config_file.NfsExport'>
<class 'grr_response_core.lib.rdfvalues.config_file.SshdMatchBlock'>
<class 'grr_response_core.lib.rdfvalues.config_file.SshdConfig'>
<class 'grr_response_core.lib.rdfvalues.config_file.NtpConfig'>
<class 'grr_response_core.lib.rdfvalues.config_file.PamConfigEntry'>
<class 'grr_response_core.lib.rdfvalues.config_file.PamConfig'>
<class 'grr_response_core.lib.rdfvalues.config_file.SudoersAlias'>
<class 'grr_response_core.lib.rdfvalues.config_file.SudoersDefault'>
<class 'grr_response_core.lib.rdfvalues.config_file.SudoersEntry'>
<class 'grr_response_core.lib.rdfvalues.config_file.SudoersConfig'>
<class 'grr_response_core.lib.parsers.config_file.NfsExportsParser'>
<class 'grr_response_core.lib.parsers.config_file.SshdConfigParser'>
<class 'grr_response_core.lib.parsers.config_file.SshdConfigCmdParser'>
<class 'grr_response_core.lib.parsers.config_file.MtabParser'>
<class 'grr_response_core.lib.parsers.config_file.MountCmdParser'>
<class 'grr_response_core.lib.parsers.config_file.RsyslogParser'>
<class 'grr_response_core.lib.parsers.config_file.PackageSourceParser'>
<class 'grr_response_core.lib.parsers.config_file.APTPackageSourceParser'>
<class 'grr_response_core.lib.parsers.config_file.YumPackageSourceParser'>
<class 'grr_response_core.lib.parsers.config_file.CronAtAllowDenyParser'>
<class 'grr_response_core.lib.parsers.config_file.NtpdParser'>
<class 'grr_response_core.lib.parsers.config_file.SudoersParser'>
<class 'grr_response_core.lib.parsers.cron_file_parser.CronTabParser'>
<class 'grr_response_core.lib.rdfvalues.webhistory.BrowserHistoryItem'>
<class 'grr_response_core.lib.parsers.ie_history.IEHistoryParser'>
<class 'grr_response_core.lib.parsers.linux_cmd_parser.YumListCmdParser'>
<class 'grr_response_core.lib.parsers.linux_cmd_parser.YumRepolistCmdParser'>
<class 'grr_response_core.lib.parsers.linux_cmd_parser.RpmCmdParser'>
<class 'grr_response_core.lib.parsers.linux_cmd_parser.DpkgCmdParser'>
<class 'grr_response_core.lib.parsers.linux_cmd_parser.DmidecodeCmdParser'>
<class 'grr_response_core.lib.parsers.linux_cmd_parser.PsCmdParser'>
<class 'grr_response_core.lib.parsers.linux_file_parser.PCIDevicesInfoParser'>
<class 'grr_response_core.lib.parsers.linux_file_parser.PasswdParser'>
<class 'grr_response_core.lib.parsers.linux_file_parser.PasswdBufferParser'>
<class 'grr_response_core.lib.parsers.linux_file_parser.LinuxWtmpParser'>
<class 'grr_response_core.lib.parsers.linux_file_parser.NetgroupParser'>
<class 'grr_response_core.lib.parsers.linux_file_parser.NetgroupBufferParser'>
<class 'grr_response_core.lib.parsers.linux_file_parser.LinuxBaseShadowParser'>
<class 'grr_response_core.lib.parsers.linux_file_parser.LinuxSystemGroupParser'>
<class 'grr_response_core.lib.parsers.linux_file_parser.LinuxSystemPasswdParser'>
<class 'grr_response_core.lib.parsers.linux_file_parser.PathParser'>
<class 'grr_response_core.lib.parsers.linux_pam_parser.PAMParser'>
<class 'grr_response_core.lib.parsers.linux_release_parser.LinuxReleaseParser'>
<class 'grr_response_core.lib.parsers.linux_service_parser.LinuxLSBInitParser'>
<class 'grr_response_core.lib.parsers.linux_service_parser.LinuxXinetdParser'>
<class 'grr_response_core.lib.parsers.linux_service_parser.LinuxSysVInitParser'>
<class 'grr_response_core.lib.parsers.linux_sysctl_parser.ProcSysParser'>
<class 'grr_response_core.lib.parsers.linux_sysctl_parser.SysctlCmdParser'>
<class 'grr_response_core.lib.rdfvalues.plist.FilterString'>
<class 'grr_response_core.lib.rdfvalues.plist.PlistQuery'>
<class 'grr_response_core.lib.rdfvalues.plist.PlistBoolDictEntry'>
<class 'grr_response_core.lib.rdfvalues.plist.PlistStringDictEntry'>
<class 'grr_response_core.lib.rdfvalues.plist.PlistRequest'>
<class 'grr_response_core.lib.rdfvalues.plist.LaunchdStartCalendarIntervalEntry'>
<class 'grr_response_core.lib.rdfvalues.plist.LaunchdKeepAlive'>
<class 'grr_response_core.lib.rdfvalues.plist.LaunchdPlist'>
<class 'grr_response_core.lib.parsers.osx_file_parser.OSXUsersParser'>
<class 'grr_response_core.lib.parsers.osx_file_parser.OSXSPHardwareDataTypeParser'>
<class 'grr_response_core.lib.parsers.osx_file_parser.OSXLaunchdPlistParser'>
<class 'grr_response_core.lib.parsers.osx_file_parser.OSXInstallHistoryPlistParser'>
<class 'grr_response_core.lib.parsers.osx_launchd.DarwinPersistenceMechanismsParser'>
<class 'grr_response_core.lib.parsers.windows_persistence.WindowsPersistenceMechanismsParser'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.CurrentControlSetKBParser'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.WinEnvironmentParser'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.WinSystemDriveParser'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.WinSystemRootParser'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.CodepageParser'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.ProfilesDirectoryEnvironmentVariable'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.AllUsersProfileEnvironmentVariable'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.WinUserSids'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.WinUserSpecialDirs'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.WinServicesParser'>
<class 'grr_response_core.lib.parsers.windows_registry_parser.WinTimezoneParser'>
<class 'grr_response_core.lib.rdfvalues.wmi.WMIActiveScriptEventConsumer'>
<class 'grr_response_core.lib.rdfvalues.wmi.WMICommandLineEventConsumer'>
<class 'grr_response_core.lib.parsers.wmi_parser.WMIEventConsumerParser'>
<class 'grr_response_core.lib.parsers.wmi_parser.WMIActiveScriptEventConsumerParser'>
<class 'grr_response_core.lib.parsers.wmi_parser.WMICommandLineEventConsumerParser'>
<class 'grr_response_core.lib.parsers.wmi_parser.WMIInstalledSoftwareParser'>
<class 'grr_response_core.lib.parsers.wmi_parser.WMIHotfixesSoftwareParser'>
<class 'grr_response_core.lib.parsers.wmi_parser.WMIUserParser'>
<class 'grr_response_core.lib.parsers.wmi_parser.WMILogicalDisksParser'>
<class 'grr_response_core.lib.parsers.wmi_parser.WMIComputerSystemProductParser'>
<class 'grr_response_core.lib.parsers.wmi_parser.WMIInterfacesParser'>
<class 'grr_response_core.lib.parsers.linux_software_parser.DebianPackagesStatusParser'>
<class 'grr_response_core.lib.rdfvalues.artifacts.ArtifactSource'>
<class 'grr_response_core.lib.rdfvalues.artifacts.ArtifactName'>
<class 'grr_response_core.lib.rdfvalues.artifacts.Artifact'>
<class 'grr_response_core.lib.rdfvalues.artifacts.ArtifactProcessorDescriptor'>
<class 'grr_response_core.lib.rdfvalues.artifacts.ArtifactDescriptor'>
<class 'grr_response_core.lib.rdfvalues.artifacts.ExpandedSource'>
<class 'grr_response_core.lib.rdfvalues.artifacts.ExpandedArtifact'>
<class 'grr_response_core.lib.rdfvalues.artifacts.ArtifactCollectorFlowArgs'>
<class 'grr_response_core.lib.rdfvalues.artifacts.ClientArtifactCollectorArgs'>
<class 'grr_response_core.lib.rdfvalues.artifacts.ClientActionResult'>
<class 'grr_response_core.lib.rdfvalues.artifacts.CollectedArtifact'>
<class 'grr_response_core.lib.rdfvalues.artifacts.ClientArtifactCollectorResult'>
<class 'grr_response_client.client_actions.artifact_collector.ArtifactCollector'>
<class 'grr_response_core.lib.rdfvalues.cloud.CloudMetadataRequest'>
<class 'grr_response_core.lib.rdfvalues.cloud.CloudMetadataRequests'>
<class 'grr_response_core.lib.rdfvalues.cloud.CloudMetadataResponse'>
<class 'grr_response_core.lib.rdfvalues.cloud.CloudMetadataResponses'>
<class 'grr_response_core.lib.rdfvalues.cloud.GoogleCloudInstance'>
<class 'grr_response_core.lib.rdfvalues.cloud.AmazonCloudInstance'>
<class 'grr_response_core.lib.rdfvalues.cloud.CloudInstance'>
<class 'grr_response_client.client_actions.cloud.GetCloudVMMetadata'>
<class 'grr_response_client.client_actions.enrol.SaveCert'>
<class 'grr_response_client.client_actions.file_fingerprint.FingerprintFile'>
<class 'grr_response_core.lib.rdfvalues.osquery.OsqueryArgs'>
<class 'grr_response_core.lib.rdfvalues.osquery.OsqueryColumn'>
<class 'grr_response_core.lib.rdfvalues.osquery.OsqueryHeader'>
<class 'grr_response_core.lib.rdfvalues.osquery.OsqueryRow'>
<class 'grr_response_core.lib.rdfvalues.osquery.OsqueryTable'>
<class 'grr_response_core.lib.rdfvalues.osquery.OsqueryResult'>
<class 'grr_response_client.client_actions.osquery.Osquery'>
<class 'grr_response_client.client_actions.plist.PlistQuery'>
<class 'grr_response_client.client_actions.searching.Find'>
<class 'grr_response_client.client_actions.searching.Grep'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraSignature'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessScanRequest'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessError'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraStringMatch'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraMatch'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessScanMatch'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessScanMiss'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessScanResponse'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessDumpArgs'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessDumpInformation'>
<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessDumpResponse'>
<class 'grr_response_client.client_actions.yara_actions.YaraProcessScan'>
<class 'grr_response_client.client_actions.yara_actions.YaraProcessDump'>
<class 'grr_response_client.vfs_handlers.sleuthkit.TSKFile'>
<class 'grr_response_core.lib.rdfvalues.stats.Distribution'>
<class 'grr_response_core.lib.rdfvalues.stats.MetricFieldDefinition'>
<class 'grr_response_core.lib.rdfvalues.stats.MetricMetadata'>
<class 'grr_response_core.lib.rdfvalues.stats.StatsHistogramBin'>
<class 'grr_response_core.lib.rdfvalues.stats.StatsHistogram'>
<class 'grr_response_core.lib.rdfvalues.stats.RunningStats'>
<class 'grr_response_core.lib.rdfvalues.stats.ClientResourcesStats'>
<class 'grr_response_core.lib.rdfvalues.stats.Sample'>
<class 'grr_response_core.lib.rdfvalues.stats.SampleFloat'>
<class 'grr_response_core.lib.rdfvalues.stats.Graph'>
<class 'grr_response_core.lib.rdfvalues.stats.GraphFloat'>
<class 'grr_response_core.lib.rdfvalues.stats.GraphSeries'>
<class 'grr_response_core.lib.rdfvalues.stats.ClientGraphSeries'>
<class 'grr_response_core.lib.parsers.chrome_history.ChromeHistoryParser'>
<class 'grr_response_core.lib.parsers.firefox3_history.FirefoxHistoryParser'>
<class 'grr_response_client.installer.Installer'>


9. got the following error:
ERROR:2019-02-25 20:13:52,963 23316 MainProcess 139899981432576 Thread-5 frontend:205] Had to respond with status 500.
Traceback (most recent call last):
  File "/home/samanoudy/grr/grr/server/grr_response_server/bin/frontend.py", line 199, in do_POST
    self.Control()
  File "/home/samanoudy/grr/grr/core/grr_response_core/stats/stats_utils.py", line 55, in Decorated
    return func(*args, **kwargs)
  File "/home/samanoudy/grr/grr/core/grr_response_core/stats/stats_utils.py", line 33, in Decorated
    return func(*args, **kwargs)
  File "/home/samanoudy/grr/grr/server/grr_response_server/bin/frontend.py", line 267, in Control
    self.Send(responses_comms.SerializeToString())
  File "/home/samanoudy/grr/grr/server/grr_response_server/bin/frontend.py", line 92, in Send
    self.wfile.write(data)
  File "/usr/lib/python2.7/socket.py", line 328, in write
    self.flush()
  File "/usr/lib/python2.7/socket.py", line 307, in flush
    self._sock.sendall(view[write_offset:write_offset+buffer_size])
error: [Errno 32] Broken pipe
----------------------------------------
Exception happened during processing of request from ('::ffff:127.0.0.1', 45936, 0, 0)
Traceback (most recent call last):
  File "/usr/lib/python2.7/SocketServer.py", line 596, in process_request_thread
    self.finish_request(request, client_address)
  File "/usr/lib/python2.7/SocketServer.py", line 331, in finish_request
    self.RequestHandlerClass(request, client_address, self)
  File "/usr/lib/python2.7/SocketServer.py", line 654, in __init__
    self.finish()
  File "/usr/lib/python2.7/SocketServer.py", line 713, in finish
    self.wfile.close()
  File "/usr/lib/python2.7/socket.py", line 283, in close
    self.flush()
  File "/usr/lib/python2.7/socket.py", line 307, in flush
    self._sock.sendall(view[write_offset:write_offset+buffer_size])
error: [Errno 32] Broken pipe


11. plugin feature of classes:
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
TypeInfoObject
TypeInfoObject
TypeInfoObject
TypeInfoObject
TypeInfoObject
TypeInfoObject
TypeInfoObject
TypeInfoObject
TypeInfoObject
TypeInfoObject
TypeInfoObject
TypeInfoObject
TypeInfoObject
TypeInfoObject
TypeInfoObject
TypeInfoObject
TypeInfoObject
TypeInfoObject
TypeInfoObject
TypeInfoObject
RDFValue
TypeInfoObject
TypeInfoObject
TypeInfoObject
TypeInfoObject
TypeInfoObject
TypeInfoObject
TypeInfoObject
RDFValue
RDFValue
RDFValue
RDFValue
ConfigFilter
ConfigFilter
ConfigFilter
ConfigFilter
ConfigFilter
ConfigFilter
ConfigFilter
ConfigFilter
ConfigFilter
ConfigFilter
ConfigFilter
ConfigFilter
GRRConfigParser
GRRConfigParser
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
TypeInfoObject
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
InitHook
VFSHandler
VFSHandler
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
RDFValue
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
RDFValue
RDFValue
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
Parser
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
VFSHandler
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
RDFValue
Parser
Parser


12. base classes example:
(<class 'grr_response_core.lib.registry.HookRegistry'>,)
(<type 'object'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFValue'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFPrimitive'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFBytes'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFPrimitive'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFBytes'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFPrimitive'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFInteger'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFInteger'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFInteger'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFInteger'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFPrimitive'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFURN'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFURN'>,)
(<class 'grr_response_core.lib.rdfvalue.SessionID'>,)
(<type 'object'>,)
(<class 'grr_response_core.lib.type_info.TypeInfoObject'>,)
(<class 'grr_response_core.lib.type_info.TypeInfoObject'>,)
(<class 'grr_response_core.lib.type_info.TypeInfoObject'>,)
(<class 'grr_response_core.lib.type_info.TypeInfoObject'>,)
(<class 'grr_response_core.lib.type_info.TypeInfoObject'>,)
(<class 'grr_response_core.lib.type_info.String'>,)
(<class 'grr_response_core.lib.type_info.TypeInfoObject'>,)
(<class 'grr_response_core.lib.type_info.Integer'>,)
(<class 'grr_response_core.lib.type_info.TypeInfoObject'>,)
(<class 'grr_response_core.lib.type_info.TypeInfoObject'>,)
(<class 'grr_response_core.lib.type_info.TypeInfoObject'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.ProtoType'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.ProtoType'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.ProtoType'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.ProtoUnsignedInteger'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.ProtoUnsignedInteger'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.ProtoFixed32'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.ProtoFixed32'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.ProtoFixed32'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.ProtoFixed64'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFInteger'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.ProtoSignedInteger'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.ProtoEnum'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.ProtoType'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.ProtoType'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.ProtoDynamicEmbedded'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.ProtoType'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.ProtoType'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFValue'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<type 'object'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<type 'object'>,)
(<class 'grr_response_core.lib.config_lib.ConfigFilter'>,)
(<class 'grr_response_core.lib.config_lib.ConfigFilter'>,)
(<class 'grr_response_core.lib.config_lib.ConfigFilter'>,)
(<class 'grr_response_core.lib.config_lib.ConfigFilter'>,)
(<class 'grr_response_core.lib.config_lib.ConfigFilter'>,)
(<class 'grr_response_core.lib.config_lib.ConfigFilter'>,)
(<class 'grr_response_core.lib.config_lib.ConfigFilter'>,)
(<class 'grr_response_core.lib.config_lib.ConfigFilter'>,)
(<class 'grr_response_core.lib.config_lib.ConfigFilter'>,)
(<class 'grr_response_core.lib.config_lib.ConfigFilter'>,)
(<class 'grr_response_core.lib.config_lib.ConfigFilter'>,)
(<class 'grr_response_core.lib.config_lib.ConfigFilter'>,)
(<type 'object'>,)
(<class 'backports.configparser.RawConfigParser'>, <class 'grr_response_core.lib.config_lib.GRRConfigParser'>)
(<class 'grr_response_core.lib.config_lib.GRRConfigParser'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFString'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFBytes'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFString'>,)
(<class 'grr_response_core.lib.rdfvalues.standard.EmailAddress'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFPrimitive'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFValue'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFPrimitive'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFPrimitive'>,)
(<class 'grr_response_core.lib.rdfvalues.crypto.RSAPrivateKey'>,)
(<class 'grr_response_core.lib.rdfvalues.crypto.RSAPublicKey'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFBytes'>,)
(<class 'grr_response_core.lib.rdfvalues.crypto.EncryptionKey'>,)
(<class 'grr_response_core.lib.rdfvalues.crypto.AES128Key'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFString'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.protodict.Dict'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.protodict.RDFValueArray'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.protodict.RDFValueArray'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFInteger'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFInteger'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFInteger'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.protodict.RDFValueArray'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFBytes'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.protodict.RDFValueArray'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFURN'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.client.User'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.protodict.RDFValueArray'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.protodict.RDFValueArray'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFString'>,)
(<class 'grr_response_core.lib.type_info.String'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.protodict.RDFValueArray'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.stats.Graph'>,)
(<class 'grr_response_core.lib.rdfvalues.protodict.RDFValueArray'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFValue'>,)
(<class 'grr_response_server.rdfvalues.objects.HashID'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.rdfvalues.objects.HashID'>,)
(<class 'grr_response_server.rdfvalues.objects.HashID'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFString'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.foreman_rules.ForemanClientRuleBase'>,)
(<class 'grr_response_server.foreman_rules.ForemanClientRuleBase'>,)
(<class 'grr_response_server.foreman_rules.ForemanClientRuleBase'>,)
(<class 'grr_response_server.foreman_rules.ForemanClientRuleBase'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.foreman_rules.ForemanClientRuleBase'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.protodict.RDFValueArray'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<type 'object'>,)
(<class 'grr_response_server.output_plugin.OutputPlugin'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.rdfvalues.flow_objects.FlowMessage'>, <class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>)
(<class 'grr_response_server.rdfvalues.flow_objects.FlowMessage'>, <class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>)
(<class 'grr_response_server.rdfvalues.flow_objects.FlowMessage'>, <class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<type 'object'>,)
(<class 'grr_response_core.lib.registry.InitHook'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFString'>,)
(<type 'object'>,)
(<class 'grr_response_server.aff4.AFF4Object'>,)
(<class 'grr_response_server.aff4.AFF4Volume'>,)
(<class 'grr_response_server.aff4.AFF4Object'>,)
(<class 'grr_response_server.aff4.AFF4Object'>,)
(<class 'grr_response_server.aff4.AFF4Stream'>,)
(<class 'grr_response_server.aff4.AFF4MemoryStreamBase'>,)
(<class 'grr_response_server.aff4.AFF4MemoryStreamBase'>,)
(<class 'grr_response_server.aff4.AFF4Stream'>,)
(<class 'grr_response_server.aff4.AFF4ImageBase'>,)
(<class 'grr_response_server.aff4.AFF4ImageBase'>,)
(<class 'grr_response_core.lib.registry.InitHook'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<type 'object'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFString'>,)
(<class 'grr_response_core.lib.rdfvalues.plist.FilterString'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFString'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<type 'object'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.GetClientStats'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_server.server_stubs.ClientActionStub'>,)
(<class 'grr_response_core.lib.registry.InitHook'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFString'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.aff4.AFF4Object'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.aff4.AFF4Volume'>,)
(<class 'grr_response_server.flow.FlowBase'>,)
(<class 'grr_response_server.flow.GRRFlow'>,)
(<class 'grr_response_server.aff4.AFF4Volume'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFBytes'>,)
(<class 'grr_response_server.aff4.AFF4ImageBase'>,)
(<class 'grr_response_server.aff4.AFF4Object'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFString'>,)
(<class 'grr_response_server.aff4_objects.standard.VFSDirectory'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flow.GRRFlow'>,)
(<class 'grr_response_server.aff4.AFF4Image'>,)
(<class 'grr_response_server.aff4.AFF4MemoryStream'>,)
(<class 'grr_response_server.aff4.AFF4Object'>,)
(<class 'grr_response_core.lib.registry.InitHook'>,)
(<class 'grr_response_server.aff4.AFF4Stream'>,)
(<class 'grr_response_server.aff4_objects.aff4_grr.VFSFile'>,)
(<class 'grr_response_server.aff4_objects.standard.VFSDirectory'>,)
(<class 'grr_response_server.aff4.AFF4Volume'>,)
(<class 'grr_response_server.aff4_objects.aff4_grr.VFSBlobImage'>,)
(<class 'grr_response_core.lib.rdfvalue.RDFURN'>,)
(<class 'grr_response_server.aff4_objects.filestore.FileStore'>,)
(<class 'grr_response_server.aff4_objects.filestore.FileStoreImage'>,)
(<class 'grr_response_server.aff4_objects.filestore.HashFileStore'>,)
(<class 'grr_response_core.lib.registry.InitHook'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<type 'object'>,)
(<class 'grr_response_core.lib.parser.Parser'>, <class 'grr_response_core.lib.parser.SingleResponseParser'>)
(<class 'grr_response_core.lib.parser.Parser'>, <class 'grr_response_core.lib.parser.SingleFileParser'>)
(<class 'grr_response_core.lib.parser.Parser'>, <class 'grr_response_core.lib.parser.MultiFileParser'>)
(<class 'grr_response_core.lib.parser.Parser'>, <class 'grr_response_core.lib.parser.SingleResponseParser'>)
(<class 'grr_response_core.lib.parser.Parser'>, <class 'grr_response_core.lib.parser.SingleResponseParser'>)
(<class 'grr_response_core.lib.parser.Parser'>, <class 'grr_response_core.lib.parser.SingleResponseParser'>)
(<class 'grr_response_core.lib.parser.Parser'>, <class 'grr_response_core.lib.parser.MultiResponseParser'>)
(<class 'grr_response_core.lib.parser.Parser'>, <class 'grr_response_core.lib.parser.SingleResponseParser'>)
(<class 'grr_response_core.lib.parser.Parser'>, <class 'grr_response_core.lib.parser.SingleResponseParser'>)
(<class 'grr_response_core.lib.parser.Parser'>, <class 'grr_response_core.lib.parser.MultiResponseParser'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.parser.FileParser'>,)
(<class 'grr_response_core.lib.parser.FileParser'>,)
(<class 'grr_response_core.lib.parser.CommandParser'>,)
(<class 'grr_response_core.lib.parser.FileParser'>,)
(<class 'grr_response_core.lib.parser.CommandParser'>,)
(<class 'grr_response_core.lib.parser.FileMultiParser'>,)
(<class 'grr_response_core.lib.parser.FileParser'>,)
(<class 'grr_response_core.lib.parsers.config_file.PackageSourceParser'>,)
(<class 'grr_response_core.lib.parsers.config_file.PackageSourceParser'>,)
(<class 'grr_response_core.lib.parser.FileParser'>,)
(<class 'grr_response_core.lib.parser.FileParser'>,)
(<class 'grr_response_core.lib.parser.FileParser'>,)
(<class 'grr_response_core.lib.parser.FileParser'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.parser.FileParser'>,)
(<class 'grr_response_core.lib.parser.CommandParser'>,)
(<class 'grr_response_core.lib.parser.CommandParser'>,)
(<class 'grr_response_core.lib.parser.CommandParser'>,)
(<class 'grr_response_core.lib.parser.CommandParser'>,)
(<class 'grr_response_core.lib.parser.CommandParser'>,)
(<class 'grr_response_core.lib.parser.CommandParser'>,)
(<class 'grr_response_core.lib.parser.FileMultiParser'>,)
(<class 'grr_response_core.lib.parser.FileParser'>,)
(<class 'grr_response_core.lib.parser.GrepParser'>,)
(<class 'grr_response_core.lib.parser.FileParser'>,)
(<class 'grr_response_core.lib.parser.FileParser'>,)
(<class 'grr_response_core.lib.parser.GrepParser'>,)
(<class 'grr_response_core.lib.parser.FileMultiParser'>,)
(<class 'grr_response_core.lib.parsers.linux_file_parser.LinuxBaseShadowParser'>,)
(<class 'grr_response_core.lib.parsers.linux_file_parser.LinuxBaseShadowParser'>,)
(<class 'grr_response_core.lib.parser.FileParser'>,)
(<class 'grr_response_core.lib.parser.FileMultiParser'>,)
(<class 'grr_response_core.lib.parser.FileMultiParser'>,)
(<class 'grr_response_core.lib.parser.FileMultiParser'>,)
(<class 'grr_response_core.lib.parser.FileMultiParser'>,)
(<class 'grr_response_core.lib.parser.FileMultiParser'>,)
(<class 'grr_response_core.lib.parser.FileMultiParser'>,)
(<class 'grr_response_core.lib.parser.CommandParser'>,)
(<class 'grr_response_core.lib.parser.ArtifactFilesMultiParser'>,)
(<class 'grr_response_core.lib.parser.CommandParser'>,)
(<class 'grr_response_core.lib.parser.FileParser'>,)
(<class 'grr_response_core.lib.parser.FileParser'>,)
(<class 'grr_response_core.lib.parser.ArtifactFilesParser'>,)
(<class 'grr_response_core.lib.parser.ArtifactFilesParser'>,)
(<class 'grr_response_core.lib.parser.RegistryValueParser'>,)
(<class 'grr_response_core.lib.parser.RegistryValueParser'>,)
(<class 'grr_response_core.lib.parser.RegistryValueParser'>,)
(<class 'grr_response_core.lib.parser.RegistryValueParser'>,)
(<class 'grr_response_core.lib.parser.RegistryValueParser'>,)
(<class 'grr_response_core.lib.parser.RegistryParser'>,)
(<class 'grr_response_core.lib.parser.RegistryParser'>,)
(<class 'grr_response_core.lib.parser.RegistryParser'>,)
(<class 'grr_response_core.lib.parser.RegistryMultiParser'>,)
(<class 'grr_response_core.lib.parser.RegistryValueParser'>,)
(<class 'grr_response_core.lib.parser.RegistryValueParser'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.parser.WMIQueryParser'>,)
(<class 'grr_response_core.lib.parsers.wmi_parser.WMIEventConsumerParser'>,)
(<class 'grr_response_core.lib.parsers.wmi_parser.WMIEventConsumerParser'>,)
(<class 'grr_response_core.lib.parser.WMIQueryParser'>,)
(<class 'grr_response_core.lib.parser.WMIQueryParser'>,)
(<class 'grr_response_core.lib.parser.WMIQueryParser'>,)
(<class 'grr_response_core.lib.parser.WMIQueryParser'>,)
(<class 'grr_response_core.lib.parser.WMIQueryParser'>,)
(<class 'grr_response_core.lib.parser.WMIQueryParser'>,)
(<class 'grr_response_core.lib.parser.FileParser'>,)
(<class 'grr_response_server.aff4.AFF4Object'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.aff4_objects.aff4_queue.Queue'>,)
(<class 'grr_response_core.lib.registry.InitHook'>,)
(<type 'object'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.artifact.KnowledgeBaseInitializationFlowMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.artifact.KnowledgeBaseInitializationFlowMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.registry.InitHook'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.artifact_fallbacks.SystemRootSystemDriveFallbackFlowMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.artifact_fallbacks.SystemRootSystemDriveFallbackFlowMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_server.flows.general.artifact_fallbacks.WindowsAllUsersProfileFallbackFlowMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.artifact_fallbacks.WindowsAllUsersProfileFallbackFlowMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.transfer.GetFileMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.transfer.GetFileMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.transfer.MultiGetFileMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.transfer.MultiGetFileMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_server.events.EventListener'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.transfer.GetMBRMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.transfer.GetMBRMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_server.flow.WellKnownFlow'>,)
(<class 'grr_response_server.flows.general.transfer.SendFileMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.transfer.SendFileMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.filesystem.ListDirectoryMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.filesystem.ListDirectoryMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.filesystem.RecursiveListDirectoryMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.filesystem.RecursiveListDirectoryMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.filesystem.UpdateSparseImageChunksMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.filesystem.UpdateSparseImageChunksMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.filesystem.FetchBufferForSparseImageMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.filesystem.FetchBufferForSparseImageMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flow.GRRFlow'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.filesystem.GlobMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.filesystem.GlobMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.filesystem.DiskVolumeInfoMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.filesystem.DiskVolumeInfoMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.fingerprint.FingerprintFileMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.fingerprint.FingerprintFileMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_server.flows.general.file_finder.FileFinderMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.file_finder.FileFinderMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_server.flows.general.file_finder.ClientFileFinderMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.file_finder.ClientFileFinderMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_server.flows.general.collectors.ArtifactCollectorFlowMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.collectors.ArtifactCollectorFlowMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.collectors.ArtifactFilesDownloaderFlowMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.collectors.ArtifactFilesDownloaderFlowMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_server.flows.general.collectors.ClientArtifactCollectorMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.collectors.ClientArtifactCollectorMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<type 'object'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<class 'grr_response_server.export.InterfaceToExportedNetworkInterfaceConverter'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<class 'grr_response_server.export.StatEntryToExportedFileConverter'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<class 'grr_response_server.export.CollectionConverterBase'>,)
(<class 'grr_response_server.export.CollectionConverterBase'>,)
(<class 'grr_response_server.export.CollectionConverterBase'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<class 'grr_response_server.export.ExportConverter'>,)
(<type 'object'>,)
(<class 'grr_response_server.ip_resolver.IPResolverBase'>,)
(<class 'grr_response_core.lib.registry.InitHook'>,)
(<type 'object'>,)
(<class 'grr_response_core.lib.registry.InitHook'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.output_plugin.OutputPlugin'>,)
(<type 'object'>,)
(<class 'grr_response_server.instant_output_plugin.InstantOutputPlugin'>,)
(<class 'grr_response_server.instant_output_plugin.InstantOutputPluginWithExportConversion'>,)
(<type 'object'>,)
(<class 'grr_response_server.email_alerts.EmailAlerterBase'>,)
(<class 'grr_response_core.lib.registry.InitHook'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.output_plugin.OutputPlugin'>,)
(<class 'grr_response_server.instant_output_plugin.InstantOutputPluginWithExportConversion'>,)
(<class 'grr_response_server.instant_output_plugin.InstantOutputPluginWithExportConversion'>,)
(<class 'grr_response_core.lib.registry.InitHook'>,)
(<class 'grr_response_server.aff4.AFF4Stream'>,)
(<type 'object'>,)
(<class 'grr_response_server.cronjobs.CronJobBase'>,)
(<class 'grr_response_server.flow.GRRFlow'>,)
(<class 'grr_response_server.aff4_objects.cronjobs.SystemCronFlow'>,)
(<class 'grr_response_server.aff4.AFF4Volume'>,)
(<class 'grr_response_core.lib.registry.InitHook'>,)
(<type 'object'>,)
(<class 'grr_response_server.authorization.groups.GroupAccessManager'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.registry.InitHook'>,)
(<class 'grr_response_server.aff4.AFF4Object'>,)
(<class 'grr_response_server.aff4_objects.security.Approval'>,)
(<class 'grr_response_server.aff4_objects.security.ApprovalWithApproversAndReason'>,)
(<class 'grr_response_server.aff4_objects.security.ApprovalWithApproversAndReason'>,)
(<class 'grr_response_server.aff4_objects.security.ApprovalWithApproversAndReason'>,)
(<class 'grr_response_server.aff4_objects.standard.VFSDirectory'>,)
(<class 'grr_response_server.aff4.AFF4Object'>,)
(<class 'grr_response_server.access_control.AccessControlManager'>,)
(<class 'grr_response_server.data_store.DataStore'>,)
(<class 'grr_response_server.data_store.DataStore'>,)
(<class 'grr_response_server.aff4.AFF4Object'>,)
(<class 'grr_response_server.keyword_index.AFF4KeywordIndex'>,)
(<class 'grr_response_server.aff4.AFF4Object'>,)
(<class 'grr_response_server.flow.FlowBase'>,)
(<class 'grr_response_server.aff4_objects.cronjobs.SystemCronFlow'>, <class 'grr_response_server.flows.cron.data_retention.CleanHuntsMixin'>)
(<class 'grr_response_server.cronjobs.SystemCronJobBase'>, <class 'grr_response_server.flows.cron.data_retention.CleanHuntsMixin'>)
(<class 'grr_response_server.aff4_objects.cronjobs.SystemCronFlow'>,)
(<class 'grr_response_server.cronjobs.SystemCronJobBase'>,)
(<class 'grr_response_server.aff4_objects.cronjobs.SystemCronFlow'>, <class 'grr_response_server.flows.cron.data_retention.CleanInactiveClientsMixin'>)
(<class 'grr_response_server.cronjobs.SystemCronJobBase'>, <class 'grr_response_server.flows.cron.data_retention.CleanInactiveClientsMixin'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.discovery.InterrogateMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.discovery.InterrogateMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_server.events.EventListener'>,)
(<class 'grr_response_server.cronjobs.CronJobBase'>,)
(<class 'grr_response_server.flow.GRRFlow'>,)
(<class 'grr_response_server.flow.GRRFlow'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.hunts.implementation.GRRHunt'>,)
(<class 'grr_response_server.hunts.implementation.GRRHunt'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.hunts.standard.GenericHunt'>,)
(<class 'grr_response_server.cronjobs.SystemCronJobBase'>,)
(<class 'grr_response_server.flows.cron.system.AbstractClientStatsCronJob'>,)
(<class 'grr_response_server.flows.cron.system.AbstractClientStatsCronJob'>,)
(<class 'grr_response_server.flows.cron.system.AbstractClientStatsCronJob'>,)
(<class 'grr_response_server.aff4_objects.cronjobs.SystemCronFlow'>,)
(<class 'grr_response_server.flows.cron.system.AbstractClientStatsCronFlow'>,)
(<class 'grr_response_server.flows.cron.system.AbstractClientStatsCronFlow'>,)
(<class 'grr_response_server.flows.cron.system.AbstractClientStatsCronFlow'>,)
(<class 'grr_response_server.aff4_objects.cronjobs.SystemCronFlow'>, <class 'grr_response_server.flows.cron.system.InterrogationHuntMixin'>)
(<class 'grr_response_server.cronjobs.SystemCronJobBase'>, <class 'grr_response_server.flows.cron.system.InterrogationHuntMixin'>)
(<class 'grr_response_server.aff4_objects.cronjobs.SystemCronFlow'>,)
(<class 'grr_response_server.cronjobs.SystemCronJobBase'>,)
(<class 'grr_response_server.cronjobs.SystemCronJobBase'>,)
(<class 'grr_response_server.events.EventListener'>,)
(<class 'grr_response_server.flows.general.administrative.GetClientStatsMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.administrative.GetClientStatsMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_server.flow.WellKnownFlow'>, <class 'grr_response_server.flows.general.administrative.GetClientStatsProcessResponseMixin'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.administrative.DeleteGRRTempFilesMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.administrative.DeleteGRRTempFilesMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.administrative.UninstallMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.administrative.UninstallMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_server.flows.general.administrative.KillMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.administrative.KillMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.administrative.UpdateConfigurationMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.administrative.UpdateConfigurationMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.administrative.ExecutePythonHackMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.administrative.ExecutePythonHackMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.administrative.ExecuteCommandMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.administrative.ExecuteCommandMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_server.flow.WellKnownFlow'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.administrative.OnlineNotificationMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.administrative.OnlineNotificationMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.administrative.UpdateClientMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.administrative.UpdateClientMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_server.flows.general.administrative.NannyMessageHandlerMixin'>, <class 'grr_response_server.flow.WellKnownFlow'>)
(<class 'grr_response_server.flows.general.administrative.ClientAlertHandlerMixin'>, <class 'grr_response_server.flow.WellKnownFlow'>)
(<class 'grr_response_server.flows.general.administrative.ClientStartupHandlerMixin'>, <class 'grr_response_server.flow.WellKnownFlow'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.administrative.KeepAliveMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.administrative.KeepAliveMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.administrative.LaunchBinaryMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.administrative.LaunchBinaryMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_server.events.EventListener'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.ca_enroller.CAEnrolerMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.ca_enroller.CAEnrolerMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_server.flow.WellKnownFlow'>,)
(<type 'object'>,)
(<class 'grr_response_server.check_lib.filters.Filter'>,)
(<class 'grr_response_server.check_lib.filters.Filter'>,)
(<class 'grr_response_server.check_lib.filters.ObjectFilter'>,)
(<class 'grr_response_server.check_lib.filters.ObjectFilter'>,)
(<class 'grr_response_server.check_lib.filters.Filter'>,)
(<class 'grr_response_server.check_lib.filters.Filter'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.registry.InitHook'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.checks.CheckRunnerMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.checks.CheckRunnerMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_server.flow.GRRFlow'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flow.GRRFlow'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.find.FindFilesMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.find.FindFilesMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.hardware.DumpFlashImageMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.hardware.DumpFlashImageMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.hardware.DumpACPITableMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.hardware.DumpACPITableMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.network.NetstatMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.network.NetstatMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_server.flows.general.osquery.OsqueryFlowMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.osquery.OsqueryFlowMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.processes.ListProcessesMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.processes.ListProcessesMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.registry.RegistryFinderMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.registry.RegistryFinderMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_server.flows.general.registry.CollectRunKeyBinariesMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.registry.CollectRunKeyBinariesMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.parser.FileParser'>,)
(<class 'grr_response_core.lib.parser.FileParser'>,)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.webhistory.ChromeHistoryMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.webhistory.ChromeHistoryMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.webhistory.FirefoxHistoryMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.webhistory.FirefoxHistoryMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_core.lib.rdfvalues.structs.RDFProtoStruct'>,)
(<class 'grr_response_server.flows.general.webhistory.CacheGrepMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.webhistory.CacheGrepMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_server.flow.GRRFlow'>,)
(<class 'grr_response_server.flows.general.yara_flows.YaraProcessScanMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.yara_flows.YaraProcessScanMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_server.flows.general.yara_flows.YaraDumpProcessMemoryMixin'>, <class 'grr_response_server.flow.GRRFlow'>)
(<class 'grr_response_server.flows.general.yara_flows.YaraDumpProcessMemoryMixin'>, <class 'grr_response_server.flow_base.FlowBase'>)
(<class 'grr_response_server.hunts.process_results.ProcessHuntResultCollectionsCronJob'>, <class 'grr_response_server.aff4_objects.cronjobs.LegacyCronJobAdapterMixin'>, <class 'grr_response_server.aff4_objects.cronjobs.SystemCronFlow'>)
(<class 'grr_response_server.hunts.process_results.ProcessHuntResultCollectionsCronJob'>, <class 'grr_response_server.cronjobs.SystemCronJobBase'>)



15. logic is to  # Attach the classes dict to the baseclass and have all derived classes
      # use the same one:

16. This is the env_dictionary:
{'__module__': 'grr_response_core.lib.registry', '__doc__': u'Global GRR init registry.\n\n  Any classes which extend this class will be instantiated exactly\n  once when the system is initialized. This allows plugin modules to\n  register initialization routines.\n  '}
{'__module__': 'grr_response_core.lib.rdfvalue', '__str__': <function __str__ at 0x7fd0dfd5c6e0>, 'SerializeToString': <function SerializeToString at 0x7fd0dfd5c398>, '__bool__': <function __bool__ at 0x7fd0dfd5c5f0>, 'SetRaw': <function SetRaw at 0x7fd0df8d3ed8>, 'ParseFromDatastore': <function ParseFromDatastore at 0x7fd0dfd5c1b8>, 'SerializeToDataStore': <function SerializeToDataStore at 0x7fd0dfd5c320>, '__init__': <function __init__ at 0x7fd0df8d3de8>, 'Copy': <function Copy at 0x7fd0df8d3e60>, '__doc__': u'Baseclass for values.\n\n  RDFValues are serialized to and from the data store.\n  ', '__repr__': <function __repr__ at 0x7fd0dfd5c758>, '__ne__': <function __ne__ at 0x7fd0dfd5c500>, 'context_help_url': None, 'Fields': <classmethod object at 0x7fd0dfd3a910>, 'ParseFromString': <function ParseFromString at 0x7fd0dfd5c140>, '_value': None, 'data_store_type': u'bytes', '_age': 0, '__eq__': <function __eq__ at 0x7fd0dfd5c488>, '__nonzero__': <function __nonzero__ at 0x7fd0dfd5c668>, 'FromSerializedString': <classmethod object at 0x7fd0dfd3a8d8>, 'age': <property object at 0x7fd0dfd59100>, 'FromDatastoreValue': <classmethod object at 0x7fd0dfd3a8a0>, 'dirty': False, '__hash__': <function __hash__ at 0x7fd0dfd5c578>, '__copy__': <function __copy__ at 0x7fd0df8d3f50>, 'attribute_instance': None}
{'__module__': 'grr_response_core.lib.rdfvalue', 'FromHumanReadable': <classmethod object at 0x7fd0dfd3a980>, 'ParseFromHumanReadable': <function ParseFromHumanReadable at 0x7fd0dfd5ca28>}
{'AsBytes': <function AsBytes at 0x7fd0dfd5cde8>, '__module__': 'grr_response_core.lib.rdfvalue', '__str__': <function __str__ at 0x7fd0dfd5ced8>, 'SerializeToString': <function SerializeToString at 0x7fd0dfd5ce60>, 'ParseFromString': <function ParseFromString at 0x7fd0dfd5cc80>, '_value': '', '__lt__': <function __lt__ at 0x7fd0df8d8050>, '__len__': <function __len__ at 0x7fd0df8d81b8>, 'ParseFromDatastore': <function ParseFromDatastore at 0x7fd0dfd5ccf8>, 'data_store_type': u'bytes', '__gt__': <function __gt__ at 0x7fd0df8d80c8>, '__hash__': <function __hash__ at 0x7fd0dfd5cf50>, 'ParseFromHumanReadable': <function ParseFromHumanReadable at 0x7fd0dfd5cd70>, '__eq__': <function __eq__ at 0x7fd0df8d8140>, '__doc__': u'An attribute which holds bytes.', '__init__': <function __init__ at 0x7fd0dfd5cc08>}
{'__module__': 'grr_response_core.lib.rdfvalue', '__doc__': u'Zipped bytes sequence.', 'Uncompress': <function Uncompress at 0x7fd0df8d8410>}
{'SerializeToDataStore': <function SerializeToDataStore at 0x7fd0df8d8c08>, '__module__': 'grr_response_core.lib.rdfvalue', '__getitem__': <function __getitem__ at 0x7fd0df8d8848>, 'format': <function format at 0x7fd0df8d8668>, '__str__': <function __str__ at 0x7fd0df8d8758>, 'SerializeToString': <function SerializeToString at 0x7fd0df8d8b90>, 'ParseFromString': <function ParseFromString at 0x7fd0df8d8a28>, 'ParseFromDatastore': <function ParseFromDatastore at 0x7fd0df8d8aa0>, '_value': u'', '__len__': <function __len__ at 0x7fd0df8d88c0>, 'split': <function split at 0x7fd0df8d86e0>, 'data_store_type': u'string', '__hash__': <function __hash__ at 0x7fd0df8d87d0>, 'ParseFromHumanReadable': <function ParseFromHumanReadable at 0x7fd0df8d8b18>, '__lt__': <function __lt__ at 0x7fd0df8d89b0>, '__eq__': <function __eq__ at 0x7fd0df8d8938>, '__doc__': u'Represent a simple string.', '__init__': <function __init__ at 0x7fd0df8d85f0>}
{'__ne__': <function __ne__ at 0x7fd0df8dd410>, '__module__': 'grr_response_core.lib.rdfvalue', '__str__': <function __str__ at 0x7fd0df8dd2a8>, 'HexDigest': <function HexDigest at 0x7fd0df8dd230>, 'data_store_type': u'bytes', '__hash__': <function __hash__ at 0x7fd0df8dd320>, '__eq__': <function __eq__ at 0x7fd0df8dd398>, '__doc__': u'Binary hash digest with hex string representation.'}
{'__int__': <function __int__ at 0x7fd0df8dd938>, '__module__': 'grr_response_core.lib.rdfvalue', '__add__': <function __add__ at 0x7fd0df8ddde8>, '__str__': <function __str__ at 0x7fd0df8dd758>, 'SerializeToString': <function SerializeToString at 0x7fd0df8dd1b8>, '__ror__': <function __ror__ at 0x7fd0df8ddcf8>, '__radd__': <function __radd__ at 0x7fd0df8dde60>, '__rmul__': <function __rmul__ at 0x7fd0df8df1b8>, '__truediv__': <function __truediv__ at 0x7fd0df8df2a8>, '__rsub__': <function __rsub__ at 0x7fd0df8df050>, '__and__': <function __and__ at 0x7fd0df8ddb18>, '__lt__': <function __lt__ at 0x7fd0df8ddaa0>, 'ParseFromHumanReadable': <function ParseFromHumanReadable at 0x7fd0df8dd6e0>, 'ParseFromDatastore': <function ParseFromDatastore at 0x7fd0df8dd668>, '__float__': <function __float__ at 0x7fd0df8dd9b0>, '__rand__': <function __rand__ at 0x7fd0df8ddb90>, '__iand__': <function __iand__ at 0x7fd0df8ddc08>, 'SerializeToDataStore': <function SerializeToDataStore at 0x7fd0df8dd848>, '__init__': <function __init__ at 0x7fd0df8dd140>, 'IsNumeric': <staticmethod object at 0x7fd0dfd3a9f0>, '__doc__': u'Represent an integer.', '__isub__': <function __isub__ at 0x7fd0df8df0c8>, 'ParseFromString': <function ParseFromString at 0x7fd0df8dd5f0>, '__or__': <function __or__ at 0x7fd0df8ddc80>, 'data_store_type': u'integer', '__sub__': <function __sub__ at 0x7fd0df8ddf50>, '__iadd__': <function __iadd__ at 0x7fd0df8dded8>, 'FromDatastoreValue': <classmethod object at 0x7fd0dfd3aa28>, '__ior__': <function __ior__ at 0x7fd0df8ddd70>, '__div__': <function __div__ at 0x7fd0df8df230>, '__mul__': <function __mul__ at 0x7fd0df8df140>, '__floordiv__': <function __floordiv__ at 0x7fd0df8df320>, '__hash__': <function __hash__ at 0x7fd0df8df398>, '__index__': <function __index__ at 0x7fd0df8dda28>, '__long__': <function __long__ at 0x7fd0df8dd8c0>}
{'ParseFromHumanReadable': <function ParseFromHumanReadable at 0x7fd0df8df9b0>, '__module__': 'grr_response_core.lib.rdfvalue', '__doc__': u'Boolean value.', 'data_store_type': u'unsigned_integer'}
{'__module__': 'grr_response_core.lib.rdfvalue', 'data_store_type': u'unsigned_integer', 'AsMicrosecondsSinceEpoch': <function AsMicrosecondsSinceEpoch at 0x7fd0df8df8c0>, 'FromSecondsSinceEpoch': <classmethod object at 0x7fd0dfd3aad0>, '__str__': <function __str__ at 0x7fd0df8df758>, '__rmul__': <function __rmul__ at 0x7fd0df8e1140>, 'ParseFromHumanReadable': <function ParseFromHumanReadable at 0x7fd0df8dfed8>, 'AsDatetime': <function AsDatetime at 0x7fd0df8df7d0>, '__init__': <function __init__ at 0x7fd0df8dfb90>, 'Format': <function Format at 0x7fd0df8dfc80>, 'Lerp': <classmethod object at 0x7fd0dfd3abb0>, 'Floor': <function Floor at 0x7fd0df8e1320>, 'FromHumanReadable': <classmethod object at 0x7fd0dfd3ab78>, 'Now': <classmethod object at 0x7fd0dfd3aa98>, '__doc__': u'A date and time internally stored in MICROSECONDS.', '__isub__': <function __isub__ at 0x7fd0df8e1230>, 'FromMicrosecondsSinceEpoch': <classmethod object at 0x7fd0dfd3ab08>, '__add__': <function __add__ at 0x7fd0df8dff50>, 'converter': 1000000, 'FromDatetime': <classmethod object at 0x7fd0dfd3ab40>, '__iadd__': <function __iadd__ at 0x7fd0df8e1050>, '_ParseFromHumanReadable': <classmethod object at 0x7fd0dfd3abe8>, 'AsSecondsSinceEpoch': <function AsSecondsSinceEpoch at 0x7fd0df8df848>, '__mul__': <function __mul__ at 0x7fd0df8e10c8>, '__sub__': <function __sub__ at 0x7fd0df8e11b8>}
{'__module__': 'grr_response_core.lib.rdfvalue', '__doc__': u'A DateTime class which is stored in whole seconds.', 'converter': 1}
{'__module__': 'grr_response_core.lib.rdfvalue', 'data_store_type': u'unsigned_integer', 'DIVIDERS': OrderedDict([(u'w', 604800), (u'd', 86400), (u'h', 3600), (u'm', 60), (u's', 1)]), 'SerializeToString': <function SerializeToString at 0x7fd0df8e1938>, '__rmul__': <function __rmul__ at 0x7fd0df8e1cf8>, 'ParseFromHumanReadable': <function ParseFromHumanReadable at 0x7fd0df8e1f50>, 'Expiry': <function Expiry at 0x7fd0df8e1ed8>, '__init__': <function __init__ at 0x7fd0e01bdb90>, 'FromSeconds': <classmethod object at 0x7fd0dfd3a868>, '__abs__': <function __abs__ at 0x7fd0df8e1e60>, 'Validate': <function Validate at 0x7fd0df8e1848>, '__str__': <function __str__ at 0x7fd0df8e1b18>, 'milliseconds': <property object at 0x7fd0df8e4310>, '__isub__': <function __isub__ at 0x7fd0df8e1de8>, 'seconds': <property object at 0x7fd0df8e42b8>, 'FromMicroseconds': <classmethod object at 0x7fd0dfd3a7f8>, 'ParseFromString': <function ParseFromString at 0x7fd0df8e18c0>, '__add__': <function __add__ at 0x7fd0df8e1b90>, '__iadd__': <function __iadd__ at 0x7fd0df8e1c08>, '__doc__': u'Duration value stored in seconds internally.', '__mul__': <function __mul__ at 0x7fd0df8e1c80>, 'microseconds': <property object at 0x7fd0df8e4368>, '__sub__': <function __sub__ at 0x7fd0df8e1d70>}
{'REGEX': <_sre.SRE_Pattern object at 0x7fd0dfd28168>, '__module__': 'grr_response_core.lib.rdfvalue', 'DIVIDERS': {u'': 1, u'g': 1000000000, u'm': 1000000, u'k': 1000, u'mi': 1048576, u'ki': 1024, u'gi': 1073741824}, '__str__': <function __str__ at 0x7fd0df8e72a8>, 'data_store_type': u'unsigned_integer', 'ParseFromHumanReadable': <function ParseFromHumanReadable at 0x7fd0df8e7320>, '__doc__': u'A size for bytes allowing standard unit prefixes.\n\n  We use the standard IEC 60027-2 A.2 and ISO/IEC 80000:\n  Binary units (powers of 2): Ki, Mi, Gi\n  SI units (powers of 10): k, m, g\n  ', '__init__': <function __init__ at 0x7fd0df8e7230>}
{'__module__': 'grr_response_core.lib.rdfvalue', '__str__': <function __str__ at 0x7fd0df8e7aa0>, 'SerializeToString': <function SerializeToString at 0x7fd0df8e7758>, 'Add': <function Add at 0x7fd0df8e7938>, 'Split': <function Split at 0x7fd0df8e7d70>, 'ParseFromHumanReadable': <function ParseFromHumanReadable at 0x7fd0df8e76e0>, '__lt__': <function __lt__ at 0x7fd0df8e7c80>, 'ParseFromDatastore': <function ParseFromDatastore at 0x7fd0df8e7668>, 'Update': <function Update at 0x7fd0df8e79b0>, 'SerializeToDataStore': <function SerializeToDataStore at 0x7fd0df8e77d0>, '__init__': <function __init__ at 0x7fd0df8e7500>, 'Path': <function Path at 0x7fd0df8e7cf8>, 'Copy': <function Copy at 0x7fd0df8e7a28>, '__doc__': u'An object to abstract URL manipulation.', 'ParseFromString': <function ParseFromString at 0x7fd0df8e7578>, 'RelativeName': <function RelativeName at 0x7fd0df8e7de8>, 'data_store_type': u'string', '__bool__': <function __bool__ at 0x7fd0df8e7b90>, '__eq__': <function __eq__ at 0x7fd0df8e7b18>, 'scheme': u'aff4', '__nonzero__': <function __nonzero__ at 0x7fd0df8e7c08>, 'Basename': <function Basename at 0x7fd0df8e78c0>, '_string_urn': u'', 'ParseFromUnicode': <function ParseFromUnicode at 0x7fd0df8e75f0>, '__repr__': <function __repr__ at 0x7fd0df8e7e60>, '__hash__': <unbound method RDFPrimitive.__hash__>, 'Dirname': <function Dirname at 0x7fd0df8e7848>}
{'__module__': 'grr_response_core.lib.rdfvalue', '__doc__': u'A psuedo attribute representing the subject of an AFF4 object.'}
{'FlowName': <function FlowName at 0x7fd0df8eb758>, '__module__': 'grr_response_core.lib.rdfvalue', 'Queue': <function Queue at 0x7fd0df8eb6e0>, 'Add': <function Add at 0x7fd0df8eb7d0>, 'ValidateID': <classmethod object at 0x7fd0dfd3ac90>, '__doc__': u'An rdfvalue object that represents a session_id.', '__init__': <function __init__ at 0x7fd0df8eb668>}
{'__module__': 'grr_response_core.lib.rdfvalue'}
{'_type': None, 'Help': <function Help at 0x7fd0deb81848>, 'FromString': <function FromString at 0x7fd0deb81758>, 'GetType': <function GetType at 0x7fd0deb815f0>, '__module__': 'grr_response_core.lib.type_info', 'GetDefault': <function GetDefault at 0x7fd0deb81668>, 'ToString': <function ToString at 0x7fd0deb817d0>, 'Validate': <function Validate at 0x7fd0deb816e0>, '__doc__': u'Definition of the interface for flow arg typing information.', '__init__': <function __init__ at 0x7fd0deb81578>}
{'rdfclass': <class 'grr_response_core.lib.rdfvalue.RDFValue'>, '__module__': 'grr_response_core.lib.type_info', 'FromString': <function FromString at 0x7fd0deb81b18>, 'Validate': <function Validate at 0x7fd0deb81aa0>, '__doc__': u'An arg which must be an RDFValue.', '__init__': <function __init__ at 0x7fd0deb81a28>}
{'rdfclass': <class 'grr_response_core.lib.rdfvalue.RDFValue'>, '__module__': 'grr_response_core.lib.type_info', 'FromString': <function FromString at 0x7fd0deb81d70>, 'Validate': <function Validate at 0x7fd0deb81cf8>, '__doc__': u'An arg which must be a dict that maps into an RDFStruct.', '__init__': <function __init__ at 0x7fd0deb81c80>}
{'_type': <type 'bool'>, 'FromString': <function FromString at 0x7fd0deb0a6e0>, '__module__': 'grr_response_core.lib.type_info', 'Validate': <function Validate at 0x7fd0deb0a668>, '__doc__': u'A True or False value.'}
{'_type': <type 'list'>, 'FromString': <function FromString at 0x7fd0deb0a9b0>, '__module__': 'grr_response_core.lib.type_info', 'ToString': <function ToString at 0x7fd0deb0aa28>, 'Validate': <function Validate at 0x7fd0deb0a938>, '__doc__': u'A list type. Turns another type into a list of those types.', '__init__': <function __init__ at 0x7fd0deb0a8c0>}
{'_type': <type 'unicode'>, '__module__': 'grr_response_core.lib.type_info', 'ToString': <function ToString at 0x7fd0deb0acf8>, 'Validate': <function Validate at 0x7fd0deb0ac80>, '__doc__': u'A String type.', '__init__': <function __init__ at 0x7fd0deb0ac08>}
{'_type': <type 'str'>, 'FromString': <function FromString at 0x7fd0deb0af50>, '__module__': 'grr_response_core.lib.type_info', 'ToString': <function ToString at 0x7fd0deb0c050>, 'Validate': <function Validate at 0x7fd0deb0aed8>, '__doc__': u'A Bytes type.'}
{'_type': <type 'long'>, 'FromString': <function FromString at 0x7fd0deb0c2a8>, '__module__': 'grr_response_core.lib.type_info', 'Validate': <function Validate at 0x7fd0deb0c230>, '__doc__': u'An Integer number type.'}
{'_type': <type 'float'>, 'FromString': <function FromString at 0x7fd0deb0c500>, '__module__': 'grr_response_core.lib.type_info', 'Validate': <function Validate at 0x7fd0deb0c488>, '__doc__': u'Type info describing a float.'}
{'__module__': 'grr_response_core.lib.type_info', 'Validate': <function Validate at 0x7fd0deb0c758>, '__doc__': u'A choice from a set of allowed values.', '__init__': <function __init__ at 0x7fd0deb0c6e0>}
{'__module__': 'grr_response_core.lib.type_info', 'Validate': <function Validate at 0x7fd0deb0c9b0>, '__doc__': u'Choose a list of values from a set of allowed values.', '__init__': <function __init__ at 0x7fd0deb0c938>}
{'__module__': 'grr_response_core.lib.rdfvalues.structs', '_FormatDefault': <function _FormatDefault at 0x7fd0deb296e0>, '__str__': <function __str__ at 0x7fd0deb299b0>, 'SetOwner': <function SetOwner at 0x7fd0deb29a28>, 'late_bound': False, 'owner': None, 'proto_type_name': u'string', 'encoded_tag': None, '__init__': <function __init__ at 0x7fd0deb29398>, 'ConvertToWireFormat': <function ConvertToWireFormat at 0x7fd0deb295f0>, 'Format': <function Format at 0x7fd0deb29848>, '_FormatDescriptionComment': <function _FormatDescriptionComment at 0x7fd0deb29668>, 'Validate': <function Validate at 0x7fd0deb298c0>, 'Copy': <function Copy at 0x7fd0deb29410>, 'type': None, '__doc__': u'A specific type descriptor for protobuf fields.\n\n  This is an abstract class - do not instantiate directly.\n  ', 'Definition': <function Definition at 0x7fd0deb297d0>, 'ConvertFromWireFormat': <function ConvertFromWireFormat at 0x7fd0deb29578>, 'CalculateTags': <function CalculateTags at 0x7fd0deb29488>, 'wire_type': None, 'IsDirty': <function IsDirty at 0x7fd0deb29500>, 'GetDefault': <function GetDefault at 0x7fd0deb29938>, '_FormatField': <function _FormatField at 0x7fd0deb29758>, 'set_default_on_access': False}
{'Definition': <function Definition at 0x7fd0deb29ed8>, '__module__': 'grr_response_core.lib.rdfvalues.structs', 'wire_type': 2, 'Format': <function Format at 0x7fd0deb2a050>, 'ConvertFromWireFormat': <function ConvertFromWireFormat at 0x7fd0deb29de8>, 'GetDefault': <function GetDefault at 0x7fd0deb29cf8>, 'ConvertToWireFormat': <function ConvertToWireFormat at 0x7fd0deb29e60>, '_FormatDefault': <function _FormatDefault at 0x7fd0deb29f50>, 'Validate': <function Validate at 0x7fd0deb29d70>, 'type': <class 'grr_response_core.lib.rdfvalue.RDFString'>, '__doc__': u'A string encoded in a protobuf.', '__init__': <function __init__ at 0x7fd0deb29c80>}
{'Definition': <function Definition at 0x7fd0deb2a410>, '__module__': 'grr_response_core.lib.rdfvalues.structs', 'wire_type': 2, 'Format': <function Format at 0x7fd0deb2a488>, 'ConvertToWireFormat': <function ConvertToWireFormat at 0x7fd0deb2a398>, 'ConvertFromWireFormat': <function ConvertFromWireFormat at 0x7fd0deb2a320>, 'Validate': <function Validate at 0x7fd0deb2a2a8>, '_FormatDefault': <function _FormatDefault at 0x7fd0deb2a500>, 'proto_type_name': u'bytes', 'type': <class 'grr_response_core.lib.rdfvalue.RDFBytes'>, '__doc__': u'A binary string encoded in a protobuf.', '__init__': <function __init__ at 0x7fd0deb2a230>}
{'__module__': 'grr_response_core.lib.rdfvalues.structs', 'wire_type': 0, 'ConvertFromWireFormat': <function ConvertFromWireFormat at 0x7fd0deb2a758>, 'Validate': <function Validate at 0x7fd0deb2a848>, 'ConvertToWireFormat': <function ConvertToWireFormat at 0x7fd0deb2a7d0>, '_FormatDefault': <function _FormatDefault at 0x7fd0deb2a8c0>, 'proto_type_name': u'uint64', 'type': <class 'grr_response_core.lib.rdfvalue.RDFInteger'>, '__doc__': u'An unsigned VarInt encoded in the protobuf.', '__init__': <function __init__ at 0x7fd0deb2a6e0>}
{'__module__': 'grr_response_core.lib.rdfvalues.structs', 'ConvertToWireFormat': <function ConvertToWireFormat at 0x7fd0deb2ab18>, 'ConvertFromWireFormat': <function ConvertFromWireFormat at 0x7fd0deb2aaa0>, '__doc__': u'A signed VarInt encoded in the protobuf.\n\n  Note: signed VarInts are more expensive than unsigned VarInts.\n  ', 'proto_type_name': u'int64'}
{'__module__': 'grr_response_core.lib.rdfvalues.structs', 'wire_type': 5, 'ConvertFromWireFormat': <function ConvertFromWireFormat at 0x7fd0deb2ad70>, 'ConvertToWireFormat': <function ConvertToWireFormat at 0x7fd0deb2acf8>, '_size': 4, 'proto_type_name': u'sfixed32', '__doc__': u'A 32 bit fixed unsigned integer.\n\n  The wire format is a 4 byte string, while the python type is a long.\n  '}
{'__module__': 'grr_response_core.lib.rdfvalues.structs', 'wire_type': 1, 'ConvertFromWireFormat': <function ConvertFromWireFormat at 0x7fd0deb2f050>, 'ConvertToWireFormat': <function ConvertToWireFormat at 0x7fd0deb2af50>, '_size': 8, 'proto_type_name': u'sfixed64'}
{'__module__': 'grr_response_core.lib.rdfvalues.structs', 'ConvertToWireFormat': <function ConvertToWireFormat at 0x7fd0deb2f230>, 'ConvertFromWireFormat': <function ConvertFromWireFormat at 0x7fd0deb2f2a8>, '__doc__': u'A 32 bit fixed unsigned integer.\n\n  The wire format is a 4 byte string, while the python type is a long.\n  ', 'proto_type_name': u'fixed32'}
{'__module__': 'grr_response_core.lib.rdfvalues.structs', 'ConvertToWireFormat': <function ConvertToWireFormat at 0x7fd0deb2f500>, 'ConvertFromWireFormat': <function ConvertFromWireFormat at 0x7fd0deb2f578>, 'Validate': <function Validate at 0x7fd0deb2f488>, '__doc__': u'A float.\n\n  The wire format is a 4 byte string, while the python type is a float.\n  ', 'proto_type_name': u'float'}
{'__module__': 'grr_response_core.lib.rdfvalues.structs', 'ConvertToWireFormat': <function ConvertToWireFormat at 0x7fd0deb2f7d0>, 'ConvertFromWireFormat': <function ConvertFromWireFormat at 0x7fd0deb2f848>, 'Validate': <function Validate at 0x7fd0deb2f758>, '__doc__': u'A double.\n\n  The wire format is a 8 byte string, while the python type is a float.\n  ', 'proto_type_name': u'double'}
{'__module__': 'grr_response_core.lib.rdfvalues.structs', '__str__': <function __str__ at 0x7fd0deb2fb18>, '__hash__': <unbound method RDFInteger.__hash__>, 'Copy': <function Copy at 0x7fd0deb2fb90>, '__eq__': <function __eq__ at 0x7fd0deb2faa0>, '__doc__': u'A class that wraps enums.\n\n  Enums are just integers, except when printed they have a name.\n  ', '__init__': <function __init__ at 0x7fd0deb2fa28>}
{'Definition': <function Definition at 0x7fd0deb2ff50>, '__module__': 'grr_response_core.lib.rdfvalues.structs', 'ConvertToWireFormat': <function ConvertToWireFormat at 0x7fd0deb340c8>, 'Format': <function Format at 0x7fd0deb34050>, 'ConvertFromWireFormat': <function ConvertFromWireFormat at 0x7fd0deb34140>, 'GetDefault': <function GetDefault at 0x7fd0deb2fe60>, 'Validate': <function Validate at 0x7fd0deb2fed8>, 'type': <class 'grr_response_core.lib.rdfvalues.structs.EnumNamedValue'>, '__doc__': u'An enum native proto type.\n\n  This is really encoded as an integer but only certain values are allowed.\n  ', '__init__': <function __init__ at 0x7fd0deb2fde8>}
{'__module__': 'grr_response_core.lib.rdfvalues.structs', 'ConvertFromWireFormat': <function ConvertFromWireFormat at 0x7fd0deb34488>, 'GetDefault': <function GetDefault at 0x7fd0deb34398>, 'Validate': <function Validate at 0x7fd0deb34410>, 'type': <class 'grr_response_core.lib.rdfvalue.RDFBool'>, '__doc__': u'A Boolean.', '__init__': <function __init__ at 0x7fd0deb34320>}
{'Definition': <function Definition at 0x7fd0deb349b0>, '__module__': 'grr_response_core.lib.rdfvalues.structs', 'wire_type': 2, 'Format': <function Format at 0x7fd0deb34aa0>, 'LateBind': <function LateBind at 0x7fd0deb347d0>, 'ConvertFromWireFormat': <function ConvertFromWireFormat at 0x7fd0deb346e0>, 'IsDirty': <function IsDirty at 0x7fd0deb34848>, 'GetDefault': <function GetDefault at 0x7fd0deb348c0>, 'ConvertToWireFormat': <function ConvertToWireFormat at 0x7fd0deb34758>, 'set_default_on_access': True, '_FormatField': <function _FormatField at 0x7fd0deb34a28>, 'Validate': <function Validate at 0x7fd0deb34938>, '__doc__': u'A field may be embedded as a serialized protobuf.\n\n  Embedding is more efficient than nesting since the emebedded protobuf does not\n  need to be parsed at all, if the user does not access any elements in it.\n\n  Embedded protobufs are simply serialized as bytes using the wire format\n  WIRETYPE_LENGTH_DELIMITED. Hence the wire format is a simple python string,\n  but the python format representation is an RDFProtoStruct.\n  ', '__init__': <function __init__ at 0x7fd0deb34668>}
{'__module__': 'grr_response_core.lib.rdfvalues.structs', 'wire_type': 2, 'Format': <function Format at 0x7fd0deb34ed8>, 'ConvertFromWireFormat': <function ConvertFromWireFormat at 0x7fd0deb34cf8>, 'Validate': <function Validate at 0x7fd0deb34de8>, 'GetDefault': <function GetDefault at 0x7fd0deb34e60>, 'ConvertToWireFormat': <function ConvertToWireFormat at 0x7fd0deb34d70>, 'set_default_on_access': True, '_FormatDefault': <function _FormatDefault at 0x7fd0deb34f50>, 'proto_type_name': u'bytes', '__doc__': u'An embedded field which has a dynamic type.', '__init__': <function __init__ at 0x7fd0deb34c80>}
{'__module__': 'grr_response_core.lib.rdfvalues.structs', 'ConvertToWireFormat': <function ConvertToWireFormat at 0x7fd0deb382a8>, 'TYPE_BY_WRAPPER': {u'StringValue': <class 'grr_response_core.lib.rdfvalue.RDFString'>, u'BytesValue': <class 'grr_response_core.lib.rdfvalue.RDFBytes'>, u'UInt64Value': <class 'grr_response_core.lib.rdfvalue.RDFInteger'>, u'Int64Value': <class 'grr_response_core.lib.rdfvalue.RDFInteger'>, u'UInt32Value': <class 'grr_response_core.lib.rdfvalue.RDFInteger'>}, 'ConvertFromWireFormat': <function ConvertFromWireFormat at 0x7fd0deb381b8>, '_TypeFromAnyValue': <function _TypeFromAnyValue at 0x7fd0deb38230>, 'WRAPPER_BY_TYPE': {u'integer': <class 'google.protobuf.wrappers_pb2.Int64Value'>, u'bytes': <class 'google.protobuf.wrappers_pb2.BytesValue'>, u'string': <class 'google.protobuf.wrappers_pb2.StringValue'>, u'unsigned_integer': <class 'google.protobuf.wrappers_pb2.UInt64Value'>, u'unsigned_integer_32': <class 'google.protobuf.wrappers_pb2.UInt32Value'>}, 'proto_type_name': u'google.protobuf.Any', '__doc__': u'An embedded dynamic field which that is stored as AnyValue struct.'}
{'__module__': 'grr_response_core.lib.rdfvalues.structs', 'ConvertToWireFormat': <function ConvertToWireFormat at 0x7fd0deb3d0c8>, 'Format': <function Format at 0x7fd0deb3d140>, 'ConvertFromWireFormat': <function ConvertFromWireFormat at 0x7fd0deb3d050>, 'IsDirty': <function IsDirty at 0x7fd0deb38e60>, 'GetDefault': <function GetDefault at 0x7fd0deb38ed8>, 'set_default_on_access': True, '_FormatField': <function _FormatField at 0x7fd0deb3d1b8>, 'Validate': <function Validate at 0x7fd0deb38f50>, 'AddDescriptor': <function AddDescriptor at 0x7fd0deb3d2a8>, '__doc__': u'A repeated type.', '__init__': <function __init__ at 0x7fd0deb38de8>, 'SetOwner': <function SetOwner at 0x7fd0deb3d230>}
{'_GetPrimitiveEncoder': <function _GetPrimitiveEncoder at 0x7fd0deb3d578>, 'Definition': <function Definition at 0x7fd0deb3d6e0>, '__module__': 'grr_response_core.lib.rdfvalues.structs', 'wire_type': 2, 'primitive_desc': None, '_kwargs': None, '__str__': <function __str__ at 0x7fd0deb3da28>, 'Format': <function Format at 0x7fd0deb3d9b0>, 'ConvertFromWireFormat': <function ConvertFromWireFormat at 0x7fd0deb3d7d0>, 'IsDirty': <function IsDirty at 0x7fd0deb3d668>, 'GetDefault': <function GetDefault at 0x7fd0deb3d5f0>, 'ConvertToWireFormat': <function ConvertToWireFormat at 0x7fd0deb3d848>, '_FormatField': <function _FormatField at 0x7fd0deb3d938>, 'LateBind': <function LateBind at 0x7fd0deb3d500>, '_PROTO_DATA_STORE_LOOKUP': {'string': <class 'grr_response_core.lib.rdfvalues.structs.ProtoString'>, 'signed_integer': <class 'grr_response_core.lib.rdfvalues.structs.ProtoSignedInteger'>, 'integer': <class 'grr_response_core.lib.rdfvalues.structs.ProtoUnsignedInteger'>, 'bytes': <class 'grr_response_core.lib.rdfvalues.structs.ProtoBinary'>, 'unsigned_integer': <class 'grr_response_core.lib.rdfvalues.structs.ProtoUnsignedInteger'>, 'unsigned_integer_32': <class 'grr_response_core.lib.rdfvalues.structs.ProtoUnsignedInteger'>}, 'Validate': <function Validate at 0x7fd0deb3d758>, 'Copy': <function Copy at 0x7fd0deb3d8c0>, 'type': None, '__doc__': u'Serialize arbitrary rdfvalue members.\n\n  RDFValue members can be serialized in a number of different ways according to\n  their preferred data_store_type member. We map the descriptions in\n  data_store_type into a suitable protobuf serialization for optimal\n  serialization. We therefore use a delegate type descriptor to best convert\n  from the RDFValue to the wire type. For example, an RDFDatetime is best\n  represented as an integer (number of microseconds since the epoch). Hence\n  RDFDatetime.SerializeToDataStore() will return an integer, and the delegate\n  will be ProtoUnsignedInteger().\n\n  To convert from the RDFValue python type to the delegate\'s wire type we\n  therefore need to make two conversions:\n\n  1) Our python format is the RDFValue -> intermediate data store format using\n  RDFValue.SerializeToDataStore(). This will produce a python object which is\n  the correct python format for the delegate primitive type descriptor.\n\n  2) Use the delegate to obtain the wire format of its own python type\n  (i.e. self.delegate.ConvertToWireFormat())\n\n  NOTE: The default value for an RDFValue is None. It is impossible for us to\n  know how to instantiate a valid default value without being told by the\n  user. This is unlike the default value for strings or ints which are "" and 0\n  respectively.\n  ', '__init__': <function __init__ at 0x7fd0deb3d488>}
{'__module__': 'grr_response_core.lib.rdfvalues.structs', 'type_description': None, '__str__': <function __str__ at 0x7fd0deb3f500>, 'SerializeToString': <function SerializeToString at 0x7fd0deb3f230>, 'CopyConstructor': <function CopyConstructor at 0x7fd0deb3dd70>, 'HasField': <function HasField at 0x7fd0deb3de60>, 'SetRawData': <function SetRawData at 0x7fd0deb3f1b8>, 'AddDescriptor': <classmethod object at 0x7fd0deb12590>, 'ParseFromDatastore': <function ParseFromDatastore at 0x7fd0deb3f320>, 'Format': <function Format at 0x7fd0deb3f488>, '__eq__': <function __eq__ at 0x7fd0deb3f398>, 'type_infos': None, '__init__': <function __init__ at 0x7fd0deb3dcf8>, 'Copy': <function Copy at 0x7fd0deb3df50>, 'ListSetFields': <function ListSetFields at 0x7fd0deb3f140>, '__ne__': <function __ne__ at 0x7fd0deb3f410>, 'protobuf': None, '__deepcopy__': <function __deepcopy__ at 0x7fd0deb3f050>, 'Clear': <function Clear at 0x7fd0deb3dde8>, 'ParseFromString': <function ParseFromString at 0x7fd0deb3f2a8>, '_data': None, 'GetRawData': <function GetRawData at 0x7fd0deb3f0c8>, '_Set': <function _Set at 0x7fd0deb3f5f0>, '__dir__': <function __dir__ at 0x7fd0deb3f578>, 'definition': None, 'Set': <function Set at 0x7fd0deb3f668>, '_CopyRawData': <function _CopyRawData at 0x7fd0deb3ded8>, 'Get': <function Get at 0x7fd0deb3f6e0>, '__doc__': u'An RDFValue object which contains fields like a struct.\n\n  Struct members contain values such as integers, strings etc. These are stored\n  in an internal data structure.\n\n  A value can be in two states, the wire format is a serialized format closely\n  resembling the state it appears on the wire. The Decoded format is the\n  representation closely representing an internal python type. The idea is that\n  converting from a serialized wire encoding to the wire format is as cheap as\n  possible. Similarly converting from a python object to the python\n  representation is also very cheap.\n\n  Lazy evaluation occurs when we need to obtain the python representation of a\n  decoded field. This allows us to skip the evaluation of complex data.\n\n  For example, suppose we have a protobuf with several "string" fields\n  (i.e. unicode objects). The wire format for a "string" field is a UTF8 encoded\n  binary string, but the python object is a unicode object.\n\n  Normally when parsing the protobuf we can extract the wire format\n  representation very cheaply, but conversion to a unicode object is quite\n  expensive. If the user never access the specific field, we can keep the\n  internal representation in wire format and not convert it to a unicode object.\n  ', 'ClearFieldsWithLabel': <function ClearFieldsWithLabel at 0x7fd0deb3f758>, 'dirty': False, '__hash__': <unbound method RDFValue.__hash__>}
{'UnionCast': <function UnionCast at 0x7fd0deb41050>, '__module__': 'grr_response_core.lib.rdfvalues.structs', '_ToPrimitive': <function _ToPrimitive at 0x7fd0deb3fc80>, '__nonzero__': <function __nonzero__ at 0x7fd0deb3fcf8>, 'protobuf': None, 'AsDict': <function AsDict at 0x7fd0deb3fb18>, 'shortest_encoded_tag': 0, 'ToPrimitiveDict': <function ToPrimitiveDict at 0x7fd0deb3fc08>, '__bool__': <function __bool__ at 0x7fd0deb3fd70>, 'EmitProto': <classmethod object at 0x7fd0deb125c8>, 'recorded_rdf_deps': None, 'FromDict': <function FromDict at 0x7fd0deb3fb90>, 'Validate': <function Validate at 0x7fd0deb3fe60>, 'longest_encoded_tag': 0, 'AddDescriptor': <classmethod object at 0x7fd0deb12638>, '__doc__': u'An RDFStruct which uses protobufs for serialization.\n\n  This implementation is faster than the standard protobuf library.\n  ', 'FromTextFormat': <classmethod object at 0x7fd0deb12600>, 'AsPrimitiveProto': <function AsPrimitiveProto at 0x7fd0deb3faa0>}
{'__module__': 'grr_response_core.lib.rdfvalues.structs', '__doc__': u'A semantic protobuf describing the .proto extension.', 'protobuf': <class 'grr_response_proto.semantic_pb2.SemanticDescriptor'>}
{'__module__': 'grr_response_core.lib.rdfvalues.structs', '__doc__': u'Protobuf with arbitrary serialized proto and its type.', 'protobuf': <class 'google.protobuf.any_pb2.Any'>}
{'CheckDataStoreAccess': <function CheckDataStoreAccess at 0x7fd0deace1b8>, '__module__': 'grr_response_server.access_control', 'CheckClientAccess': <function CheckClientAccess at 0x7fd0deb47f50>, 'CheckIfCanStartFlow': <function CheckIfCanStartFlow at 0x7fd0deace140>, 'CheckHuntAccess': <function CheckHuntAccess at 0x7fd0deace050>, '__doc__': u'A class for managing access to data resources.\n\n  This class is responsible for determining which users have access to each\n  resource.\n\n  By default it delegates some of this functionality to a UserManager class\n  which takes care of label management and user management components.\n  ', 'CheckCronJobAccess': <function CheckCronJobAccess at 0x7fd0deace0c8>}
{'SetUID': <function SetUID at 0x7fd0deace500>, '__module__': 'grr_response_server.access_control', 'supervisor': False, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>], 'RealUID': <function RealUID at 0x7fd0deace578>, '__str__': <function __str__ at 0x7fd0deace488>, 'CheckExpiry': <function CheckExpiry at 0x7fd0deace410>, 'Copy': <function Copy at 0x7fd0deace398>, '__doc__': u'The access control token.', 'protobuf': <class 'grr_response_proto.flows_pb2.ACLToken'>}
{'sensitive_arg': False, 'Filter': <function Filter at 0x7fd0dd2936e0>, '__module__': 'grr_response_core.lib.config_lib', '__doc__': u'A configuration filter can transform a configuration parameter.', 'name': u'identity'}
{'__module__': 'grr_response_core.lib.config_lib', '__doc__': u'A filter which does not interpolate.', 'name': u'literal'}
{'Filter': <function Filter at 0x7fd0dd293a28>, '__module__': 'grr_response_core.lib.config_lib', 'name': u'lower'}
{'Filter': <function Filter at 0x7fd0dd293c08>, '__module__': 'grr_response_core.lib.config_lib', 'name': u'upper'}
{'Filter': <function Filter at 0x7fd0dd293de8>, '__module__': 'grr_response_core.lib.config_lib', 'name': u'file'}
{'Filter': <function Filter at 0x7fd0dd299050>, '__module__': 'grr_response_core.lib.config_lib', 'name': u'optionalfile'}
{'Filter': <function Filter at 0x7fd0dd299230>, '__module__': 'grr_response_core.lib.config_lib', '__doc__': u'A configuration filter that fixes the path speratator.', 'name': u'fixpathsep'}
{'Filter': <function Filter at 0x7fd0dd299410>, '__module__': 'grr_response_core.lib.config_lib', 'name': u'base64'}
{'Filter': <function Filter at 0x7fd0dd2995f0>, '__module__': 'grr_response_core.lib.config_lib', '__doc__': u'Interpolate environment variables.', 'name': u'env'}
{'Filter': <function Filter at 0x7fd0dd2997d0>, '__module__': 'grr_response_core.lib.config_lib', '__doc__': u'Expands the input as a configuration parameter.', 'name': u'expand'}
{'Filter': <function Filter at 0x7fd0dd2999b0>, '__module__': 'grr_response_core.lib.config_lib', '__doc__': u'Get the parameter from the flags.', 'name': u'flags'}
{'Filter': <function Filter at 0x7fd0dd299b90>, '__module__': 'grr_response_core.lib.config_lib', 'default_package': u'grr-response-core', '__doc__': u'Locates a GRR resource that is shipped with the GRR package.\n\n  The format of the directive is "path/to/resource@package_name". If\n  package_name is not provided we use grr-resource-core by default.\n  ', 'name': u'resource'}
{'Filter': <function Filter at 0x7fd0dd299d70>, '__module__': 'grr_response_core.lib.config_lib', '__doc__': u'Locate the path to the specified module.\n\n  Note: A module is either a python file (with a .py extension) or a directory\n  with a __init__.py inside it. It is not the same as a resource (See Resource\n  above) since a module will be installed somewhere you can import it from.\n\n  Caveat: This will raise if the module is not a physically present on disk\n  (e.g. pyinstaller bundle).\n  ', 'name': u'module_path'}
{'__module__': 'grr_response_core.lib.config_lib', 'name': None, 'SaveDataToFD': <function SaveDataToFD at 0x7fd0dd2a30c8>, '__doc__': u'The base class for all GRR configuration parsers.', 'RawData': <function RawData at 0x7fd0dd2a3140>, 'SaveData': <function SaveData at 0x7fd0dd2a3050>, 'parsed': None}
{'__module__': 'grr_response_core.lib.config_lib', 'SaveDataToFD': <function SaveDataToFD at 0x7fd0dd2a3488>, '__str__': <function __str__ at 0x7fd0dd2a3398>, 'RawData': <function RawData at 0x7fd0dd2a3500>, 'SaveData': <function SaveData at 0x7fd0dd2a3410>, '__doc__': u'A parser for ini style config files.', '__init__': <function __init__ at 0x7fd0dd2a3320>}
{'__module__': 'grr_response_core.lib.config_lib', 'name': u'yaml', 'SaveDataToFD': <function SaveDataToFD at 0x7fd0dd2a3848>, '__str__': <function __str__ at 0x7fd0dd2a3758>, '_RawData': <function _RawData at 0x7fd0dd2a38c0>, 'RawData': <function RawData at 0x7fd0dd2a3938>, 'SaveData': <function SaveData at 0x7fd0dd2a37d0>, '__doc__': u'A parser for yaml style config files.', '__init__': <function __init__ at 0x7fd0dd2a36e0>}
{'__module__': 'grr_response_core.lib.rdfvalues.standard', 'context_help_url': u'investigating-with-grr/flows/literal-and-regex-matching.html#regex-matches', 'Search': <function Search at 0x7fd0dd2af140>, 'FindIter': <function FindIter at 0x7fd0dd2af230>, '__init__': <function __init__ at 0x7fd0dd2af0c8>, '__doc__': u'A semantic regular expression.', 'Match': <function Match at 0x7fd0dd2af1b8>}
{'__module__': 'grr_response_core.lib.rdfvalues.standard', 'context_help_url': u'investigating-with-grr/flows/literal-and-regex-matching.html#literal-matches', '__doc__': u'A RDFBytes literal for use in GrepSpec.'}
{'_EMAIL_REGEX': <_sre.SRE_Pattern object at 0x7fd0e1014800>, '__module__': 'grr_response_core.lib.rdfvalues.standard', '__doc__': u'An email address must be well formed.', 'ParseFromString': <function ParseFromString at 0x7fd0dd2af578>}
{'__module__': 'grr_response_core.lib.rdfvalues.standard', '__doc__': u'A more restricted email address may only address the domain.', 'ParseFromString': <function ParseFromString at 0x7fd0dd2af758>}
{'__module__': 'grr_response_core.lib.rdfvalues.standard', 'protobuf': <class 'grr_response_proto.jobs_pb2.AuthenticodeSignedData'>}
{'__module__': 'grr_response_core.lib.rdfvalues.standard', 'protobuf': <class 'grr_response_proto.jobs_pb2.PersistenceFile'>, 'rdf_deps': [u'PathSpec', <class 'grr_response_core.lib.rdfvalue.RDFURN'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.standard', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.URI'>, 'SerializeToString': <function SerializeToString at 0x7fd0dd2387d0>, 'SerializeToHumanReadable': <function SerializeToHumanReadable at 0x7fd0dd238848>, 'ParseFromString': <function ParseFromString at 0x7fd0dd2386e0>, 'ParseFromHumanReadable': <function ParseFromHumanReadable at 0x7fd0dd238758>, '__doc__': u'Represets a URI with its individual components seperated.'}
{'__module__': 'grr_response_core.lib.rdfvalues.crypto', 'protobuf': <class 'grr_response_proto.jobs_pb2.Certificate'>}
{'ClientCertFromCSR': <classmethod object at 0x7fd0dd23c4b0>, '__module__': 'grr_response_core.lib.rdfvalues.crypto', 'GetCN': <function GetCN at 0x7fd0dd243050>, 'AsPEM': <function AsPEM at 0x7fd0dd243410>, 'Verify': <function Verify at 0x7fd0dd243500>, '__str__': <function __str__ at 0x7fd0dd243488>, 'SerializeToString': <function SerializeToString at 0x7fd0dd243398>, 'ParseFromString': <function ParseFromString at 0x7fd0dd243230>, 'ParseFromDatastore': <function ParseFromDatastore at 0x7fd0dd243320>, 'GetPublicKey': <function GetPublicKey at 0x7fd0dd2430c8>, 'GetSerialNumber': <function GetSerialNumber at 0x7fd0dd243140>, '__init__': <function __init__ at 0x7fd0dd23ded8>, 'GetIssuer': <function GetIssuer at 0x7fd0dd2431b8>, 'ParseFromHumanReadable': <function ParseFromHumanReadable at 0x7fd0dd2432a8>, '__doc__': u'X509 certificates used to communicate with this client.', 'GetRawCertificate': <function GetRawCertificate at 0x7fd0dd23df50>}
{'__module__': 'grr_response_core.lib.rdfvalues.crypto', 'GetCN': <function GetCN at 0x7fd0dd243a28>, 'AsPEM': <function AsPEM at 0x7fd0dd243938>, 'Verify': <function Verify at 0x7fd0dd243b18>, '__str__': <function __str__ at 0x7fd0dd2439b0>, 'SerializeToString': <function SerializeToString at 0x7fd0dd2438c0>, 'ParseFromString': <function ParseFromString at 0x7fd0dd2437d0>, 'GetPublicKey': <function GetPublicKey at 0x7fd0dd243aa0>, '__init__': <function __init__ at 0x7fd0dd243758>, '__doc__': u'A CSR Rdfvalue.', 'ParseFromDatastore': <function ParseFromDatastore at 0x7fd0dd243848>}
{'__module__': 'grr_response_core.lib.rdfvalues.crypto', 'Encrypt': <function Encrypt at 0x7fd0dd245230>, 'GetN': <function GetN at 0x7fd0dd245050>, 'AsPEM': <function AsPEM at 0x7fd0dd245140>, 'Verify': <function Verify at 0x7fd0dd2452a8>, '__str__': <function __str__ at 0x7fd0dd2450c8>, 'SerializeToString': <function SerializeToString at 0x7fd0dd243f50>, 'ParseFromString': <function ParseFromString at 0x7fd0dd243de8>, '__init__': <function __init__ at 0x7fd0dd243cf8>, 'GetRawPublicKey': <function GetRawPublicKey at 0x7fd0dd243d70>, 'ParseFromHumanReadable': <function ParseFromHumanReadable at 0x7fd0dd243ed8>, 'KeyLen': <function KeyLen at 0x7fd0dd2451b8>, '__doc__': u'An RSA public key.', 'ParseFromDatastore': <function ParseFromDatastore at 0x7fd0dd243e60>}
{'__module__': 'grr_response_core.lib.rdfvalues.crypto', 'AsPassphraseProtectedPEM': <function AsPassphraseProtectedPEM at 0x7fd0dd245a28>, 'AsPEM': <function AsPEM at 0x7fd0dd2459b0>, '__str__': <function __str__ at 0x7fd0dd245938>, 'SerializeToString': <function SerializeToString at 0x7fd0dd2458c0>, 'Decrypt': <function Decrypt at 0x7fd0dd2456e0>, 'ParseFromString': <function ParseFromString at 0x7fd0dd2457d0>, 'Sign': <function Sign at 0x7fd0dd245668>, 'GetPublicKey': <function GetPublicKey at 0x7fd0dd2455f0>, 'ParseFromDatastore': <function ParseFromDatastore at 0x7fd0dd245848>, 'GetRawPrivateKey': <function GetRawPrivateKey at 0x7fd0dd245578>, 'GenerateKey': <classmethod object at 0x7fd0dd287868>, 'ParseFromHumanReadable': <function ParseFromHumanReadable at 0x7fd0dd245500>, 'KeyLen': <function KeyLen at 0x7fd0dd245aa0>, '__doc__': u'An RSA private key.', '__init__': <function __init__ at 0x7fd0dd245488>}
{'__module__': 'grr_response_core.lib.rdfvalues.crypto'}
{'__module__': 'grr_response_core.lib.rdfvalues.crypto'}
{'__module__': 'grr_response_core.lib.rdfvalues.crypto', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.standard.AuthenticodeSignedData'>, <class 'grr_response_core.lib.rdfvalue.HashDigest'>], '__doc__': u'A hash object containing multiple digests.', 'protobuf': <class 'grr_response_proto.jobs_pb2.Hash'>}
{'Verify': <function Verify at 0x7fd0dd253398>, '__module__': 'grr_response_core.lib.rdfvalues.crypto', 'Sign': <function Sign at 0x7fd0dd253410>, '__doc__': u'A signed blob.\n\n  The client can receive and verify a signed blob (e.g. driver or executable\n  binary). Once verified, the client may execute this.\n  ', 'protobuf': <class 'grr_response_proto.jobs_pb2.SignedBlob'>}
{'__module__': 'grr_response_core.lib.rdfvalues.crypto', 'RawBytes': <function RawBytes at 0x7fd0dd259668>, 'FromHex': <classmethod object at 0x7fd0dd2582b8>, '__str__': <function __str__ at 0x7fd0dd259398>, 'SerializeToString': <function SerializeToString at 0x7fd0dd259500>, 'ParseFromString': <function ParseFromString at 0x7fd0dd259320>, 'GenerateRandomIV': <classmethod object at 0x7fd0dd258328>, 'length': 0, 'GenerateKey': <classmethod object at 0x7fd0dd2582f0>, 'AsHexDigest': <function AsHexDigest at 0x7fd0dd259410>, '__doc__': u'Base class for encryption keys.'}
{'__module__': 'grr_response_core.lib.rdfvalues.crypto', 'length': 128}
{'__module__': 'grr_response_core.lib.rdfvalues.crypto', '__doc__': u'Like AES128Key, but its UI edit box is prefilled with generated key.', '__init__': <function __init__ at 0x7fd0dd2599b0>}
{'__module__': 'grr_response_core.lib.rdfvalues.crypto', 'Encrypt': <function Encrypt at 0x7fd0dd25e1b8>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.crypto.EncryptionKey'>], 'Decrypt': <function Decrypt at 0x7fd0dd25e230>, '__doc__': u'Abstract symmetric cipher operations.', 'Generate': <classmethod object at 0x7fd0dd287a98>, '_get_cipher': <function _get_cipher at 0x7fd0dd25e140>, 'protobuf': <class 'grr_response_proto.jobs_pb2.SymmetricCipher'>}
{'__module__': 'grr_response_core.lib.rdfvalues.crypto', '_CalculateHash': <function _CalculateHash at 0x7fd0dd25ee60>, 'protobuf': <class 'grr_response_proto.jobs_pb2.Password'>, 'CheckPassword': <function CheckPassword at 0x7fd0dd25ef50>, 'SetPassword': <function SetPassword at 0x7fd0dd25eed8>, '__doc__': u'A password stored in the database.'}
{'Insert': <function Insert at 0x7fd0dd21dcf8>, '__module__': 'grr_response_core.lib.rdfvalues.paths', 'Dirname': <function Dirname at 0x7fd0dd20d050>, 'last': <property object at 0x7fd0dd216838>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.ByteSize'>, u'PathSpec'], '__getitem__': <function __getitem__ at 0x7fd0dd21dc08>, 'Basename': <function Basename at 0x7fd0dd20d0c8>, 'AFF4Path': <function AFF4Path at 0x7fd0dd20d1b8>, 'CollapsePath': <function CollapsePath at 0x7fd0dd21dde8>, '__iter__': <function __iter__ at 0x7fd0dd21dc80>, 'Pop': <function Pop at 0x7fd0dd21de60>, 'CopyConstructor': <function CopyConstructor at 0x7fd0dd21db18>, 'AFF4_PREFIXES': {0: u'/fs/os', 1: u'/fs/tsk', 2: u'/registry', 4: u'/temp'}, 'Append': <function Append at 0x7fd0dd21dd70>, 'Validate': <function Validate at 0x7fd0dd20d140>, 'first': <property object at 0x7fd0deab58e8>, '__doc__': u'A path specification.\n\n  The pathspec protobuf is a recursive protobuf which contains components. This\n  class makes it easier to manipulate these structures by providing useful\n  helpers.\n  ', '__len__': <function __len__ at 0x7fd0dd21db90>, 'protobuf': <class 'grr_response_proto.jobs_pb2.PathSpec'>}
{'__module__': 'grr_response_core.lib.rdfvalues.paths', 'context_help_url': u'investigating-with-grr/flows/specifying-file-paths.html', '_ReplaceRegExPart': <function _ReplaceRegExPart at 0x7fd0dd232140>, 'Interpolate': <function Interpolate at 0x7fd0dd229f50>, 'InterpolateGrouping': <function InterpolateGrouping at 0x7fd0dd232050>, 'AsRegEx': <function AsRegEx at 0x7fd0dd2321b8>, '_ReplaceRegExGrouping': <function _ReplaceRegExGrouping at 0x7fd0dd2320c8>, 'REGEX_SPLIT_PATTERN': <_sre.SRE_Pattern object at 0x7fd0e10335f0>, 'Validate': <function Validate at 0x7fd0dd229ed8>, '__doc__': u'A glob expression for a client path.\n\n  A glob expression represents a set of regular expressions which match files on\n  the client. The Glob expression supports the following expansions:\n\n  1) Client attribute expansions are surrounded with %% characters. They will be\n     expanded from the client AFF4 object.\n\n  2) Groupings are collections of alternates. e.g. {foo.exe,bar.sys}\n  3) Wild cards like * and ?\n  ', 'RECURSION_REGEX': <_sre.SRE_Pattern object at 0x7fd0e0ffdc60>}
{'__module__': 'grr_response_core.lib.rdfvalues.protodict', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>], '__doc__': u'An object that contains a serialized RDFValue.', 'payload': <property object at 0x7fd0dd234310>, '__init__': <function __init__ at 0x7fd0dd232668>, 'protobuf': <class 'grr_response_proto.jobs_pb2.EmbeddedRDFValue'>}
{'__module__': 'grr_response_core.lib.rdfvalues.protodict', 'SetValue': <function SetValue at 0x7fd0dd1bd0c8>, 'rdf_deps': [u'BlobArray', u'Dict', <class 'grr_response_core.lib.rdfvalues.protodict.EmbeddedRDFValue'>], 'GetValue': <function GetValue at 0x7fd0dd1bd140>, '__doc__': u'Wrapper class for DataBlob protobuf.', 'protobuf': <class 'grr_response_proto.jobs_pb2.DataBlob'>}
{'__module__': 'grr_response_core.lib.rdfvalues.protodict', 'protobuf': <class 'grr_response_proto.jobs_pb2.KeyValue'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.DataBlob'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.protodict', '__str__': <function __str__ at 0x7fd0df808aa0>, 'SerializeToString': <function SerializeToString at 0x7fd0df8089b0>, 'SetRawData': <function SetRawData at 0x7fd0df808938>, 'FromDict': <function FromDict at 0x7fd0df808050>, 'ToDict': <function ToDict at 0x7fd0df889f50>, '__init__': <function __init__ at 0x7fd0df889ed8>, 'protobuf': <class 'grr_response_proto.jobs_pb2.Dict'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.KeyValue'>], '__contains__': <function __contains__ at 0x7fd0df808140>, 'Keys': <function Keys at 0x7fd0df808320>, 'GetRawData': <function GetRawData at 0x7fd0df808848>, '__doc__': u'A high level interface for protobuf Dict objects.\n\n  This effectively converts from a dict to a proto and back.\n  The dict may contain strings (python unicode objects), int64,\n  or binary blobs (python string objects) as keys and values.\n  ', '__len__': <function __len__ at 0x7fd0df8085f0>, '_values': None, '__getitem__': <function __getitem__ at 0x7fd0df8080c8>, 'get': <function Wrapped at 0x7fd0df808398>, 'keys': <function Wrapped at 0x7fd0df808488>, 'Items': <function Items at 0x7fd0df808230>, 'ParseFromString': <function ParseFromString at 0x7fd0df808a28>, '__setitem__': <function __setitem__ at 0x7fd0df8086e0>, 'Values': <function Values at 0x7fd0df8082a8>, '__eq__': <function __eq__ at 0x7fd0dfd5c848>, '__delitem__': <function __delitem__ at 0x7fd0df808578>, 'items': <function Wrapped at 0x7fd0df808410>, '_CopyRawData': <function _CopyRawData at 0x7fd0df8088c0>, '__iter__': <function __iter__ at 0x7fd0df808758>, 'SetItem': <function SetItem at 0x7fd0df808668>, 'values': <function Wrapped at 0x7fd0df808500>, 'GetItem': <function GetItem at 0x7fd0df8081b8>, '__hash__': <unbound method RDFProtoStruct.__hash__>}
{'__setattr__': <function __setattr__ at 0x7fd0df8071b8>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.KeyValue'>], '__module__': 'grr_response_core.lib.rdfvalues.protodict', '__getattr__': <function __getattr__ at 0x7fd0df807140>, '__doc__': u'A Dict that supports attribute indexing.', 'protobuf': <class 'grr_response_proto.jobs_pb2.AttributedDict'>}
{'__module__': 'grr_response_core.lib.rdfvalues.protodict', 'protobuf': <class 'grr_response_proto.jobs_pb2.BlobArray'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.DataBlob'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.protodict', '__nonzero__': <function __nonzero__ at 0x7fd0df807e60>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.DataBlob'>], 'Extend': <function Extend at 0x7fd0df807c80>, 'protobuf': <class 'grr_response_proto.jobs_pb2.BlobArray'>, '__getitem__': <function __getitem__ at 0x7fd0df807cf8>, 'Pop': <function Pop at 0x7fd0df807ed8>, '__iter__': <function __iter__ at 0x7fd0df807de8>, '__len__': <function __len__ at 0x7fd0df807d70>, 'Append': <function Append at 0x7fd0df807c08>, '__doc__': u'A type which serializes a list of RDFValue instances.\n\n  TODO(user): This needs to be deprecated in favor of just defining a\n  protobuf with a repeated field (This can be now done dynamically, which is the\n  main reason we used this in the past).\n  ', '__init__': <function __init__ at 0x7fd0df807b90>, 'rdf_type': None}
{'__module__': 'grr_response_core.lib.rdfvalues.client_action', 'protobuf': <class 'grr_response_proto.jobs_pb2.EchoRequest'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_action', 'protobuf': <class 'grr_response_proto.jobs_pb2.ExecuteBinaryRequest'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.crypto.SignedBlob'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.client_action', 'protobuf': <class 'grr_response_proto.jobs_pb2.ExecuteBinaryResponse'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_action', 'protobuf': <class 'grr_response_proto.jobs_pb2.ExecutePythonRequest'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.Dict'>, <class 'grr_response_core.lib.rdfvalues.crypto.SignedBlob'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.client_action', 'protobuf': <class 'grr_response_proto.jobs_pb2.ExecutePythonResponse'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_action', 'protobuf': <class 'grr_response_proto.jobs_pb2.ExecuteRequest'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_action', 'protobuf': <class 'grr_response_proto.jobs_pb2.CopyPathToFile'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.client_action', 'protobuf': <class 'grr_response_proto.jobs_pb2.ExecuteResponse'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client_action.ExecuteRequest'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.client_action', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.crypto.AES128Key'>, <class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>], '__doc__': 'Arguments for the `SendFile` action.', 'Validate': <function Validate at 0x7fd0dd1c6ed8>, 'protobuf': <class 'grr_response_proto.jobs_pb2.SendFileRequest'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_action', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.Dict'>], '__doc__': 'An Iterated client action is one which can be resumed on the client.', 'protobuf': <class 'grr_response_proto.jobs_pb2.Iterator'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_action', 'protobuf': <class 'grr_response_proto.jobs_pb2.ListDirRequest'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client_action.Iterator'>, <class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.client_action', 'protobuf': <class 'grr_response_proto.jobs_pb2.GetFileStatRequest'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.client_action', 'protobuf': <class 'grr_response_proto.jobs_pb2.FingerprintTuple'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_action', 'protobuf': <class 'grr_response_proto.jobs_pb2.FingerprintRequest'>, 'AddRequest': <function AddRequest at 0x7fd0dd1cfed8>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client_action.FingerprintTuple'>, <class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.client_action', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.Dict'>, <class 'grr_response_core.lib.rdfvalues.crypto.Hash'>, <class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>], '__doc__': 'Proto containing dicts with hashes.', 'GetFingerprint': <function GetFingerprint at 0x7fd0dd1d17d0>, 'protobuf': <class 'grr_response_proto.jobs_pb2.FingerprintResponse'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_action', 'protobuf': <class 'grr_response_proto.jobs_pb2.WmiRequest'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_action', 'protobuf': <class 'grr_response_proto.jobs_pb2.StatFSRequest'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_action', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>], '__doc__': 'Request for GetClientStats action.', 'protobuf': <class 'grr_response_proto.jobs_pb2.GetClientStatsRequest'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_action', '__doc__': 'Args for the ListNetworkConnections client action.', 'protobuf': <class 'grr_response_proto.flows_pb2.ListNetworkConnectionsArgs'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_fs', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.AttributedDict'>], '__doc__': u'A filesystem on the client.\n\n  This class describes a filesystem mounted on the client.\n  ', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.Filesystem'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_fs', '__doc__': u'An array of client filesystems.\n\n  This is used to represent the list of valid filesystems on the client.\n  ', 'rdf_type': <class 'grr_response_core.lib.rdfvalues.client_fs.Filesystem'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_fs', '__doc__': u'Representation of Window\'s special folders information for a User.\n\n  Windows maintains a list of "Special Folders" which are used to organize a\n  user\'s home directory. Knowledge about these is required in order to resolve\n  the location of user specific items, e.g. the Temporary folder, or the\n  Internet cache.\n  ', 'protobuf': <class 'grr_response_proto.jobs_pb2.FolderInformation'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_fs', '__doc__': u'A disk volume on a windows client.', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.WindowsVolume'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_fs', '__doc__': u'A disk volume on a unix client.', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.UnixVolume'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_fs', 'FreeSpacePercent': <function FreeSpacePercent at 0x7fd0dd1ebb18>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>, <class 'grr_response_core.lib.rdfvalues.client_fs.UnixVolume'>, <class 'grr_response_core.lib.rdfvalues.client_fs.WindowsVolume'>], 'protobuf': <class 'grr_response_proto.sysinfo_pb2.Volume'>, 'AUToBytes': <function AUToBytes at 0x7fd0dd1ebc08>, 'AUToGBytes': <function AUToGBytes at 0x7fd0dd1ebc80>, 'Name': <function Name at 0x7fd0dd1ebcf8>, '__doc__': u'A disk volume on the client.', 'FreeSpaceBytes': <function FreeSpaceBytes at 0x7fd0dd1ebb90>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_fs', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.DiskUsage'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_fs', '__doc__': u'A list of disk volumes on the client.', 'rdf_type': <class 'grr_response_core.lib.rdfvalues.client_fs.Volume'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_fs', '__str__': <function __str__ at 0x7fd0dd1841b8>, '__doc__': u'The mode of a file.', 'data_store_type': u'unsigned_integer'}
{'__module__': 'grr_response_core.lib.rdfvalues.client_fs', '__doc__': u'Extended file attributes for Mac (set by `chflags`).', 'data_store_type': u'unsigned_integer_32'}
{'__module__': 'grr_response_core.lib.rdfvalues.client_fs', '__doc__': u'Extended file attributes as reported by `lsattr`.', 'data_store_type': u'unsigned_integer_32'}
{'__module__': 'grr_response_core.lib.rdfvalues.client_fs', '__doc__': u'An RDF value representing an extended attributes of a file.', 'protobuf': <class 'grr_response_proto.jobs_pb2.ExtAttr'>}
{'AFF4Path': <function AFF4Path at 0x7fd0dd184cf8>, '__module__': 'grr_response_core.lib.rdfvalues.client_fs', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.DataBlob'>, <class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetimeSeconds'>, <class 'grr_response_core.lib.rdfvalues.client_fs.StatMode'>, <class 'grr_response_core.lib.rdfvalues.client_fs.StatExtFlagsOsx'>, <class 'grr_response_core.lib.rdfvalues.client_fs.StatExtFlagsLinux'>, <class 'grr_response_core.lib.rdfvalues.client_fs.ExtAttr'>], '__doc__': u'Represent an extended stat response.', 'protobuf': <class 'grr_response_proto.jobs_pb2.StatEntry'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_fs', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.paths.GlobExpression'>, <class 'grr_response_core.lib.rdfvalues.client_action.Iterator'>, <class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetime'>, <class 'grr_response_core.lib.rdfvalues.standard.RegularExpression'>, <class 'grr_response_core.lib.rdfvalues.client_fs.StatEntry'>, <class 'grr_response_core.lib.rdfvalues.client_fs.StatMode'>], '__doc__': u'A find specification.', 'Validate': <function Validate at 0x7fd0dd1a0050>, 'protobuf': <class 'grr_response_proto.jobs_pb2.FindSpec'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_fs', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.standard.LiteralExpression'>, <class 'grr_response_core.lib.rdfvalues.standard.RegularExpression'>], '__doc__': u'A GrepSpec without a target.', 'protobuf': <class 'grr_response_proto.flows_pb2.BareGrepSpec'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_fs', 'Validate': <function Validate at 0x7fd0dd1afb18>, 'protobuf': <class 'grr_response_proto.jobs_pb2.GrepSpec'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.standard.LiteralExpression'>, <class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>, <class 'grr_response_core.lib.rdfvalues.standard.RegularExpression'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.client_fs', 'rdf_deps': [], '__doc__': u'A descriptor of a file chunk stored in VFS blob image.', 'protobuf': <class 'grr_response_proto.jobs_pb2.BlobImageChunkDescriptor'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_fs', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client_fs.BlobImageChunkDescriptor'>], '__doc__': u'A descriptor of a file stored as VFS blob image.', 'protobuf': <class 'grr_response_proto.jobs_pb2.BlobImageDescriptor'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_network', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.NetworkEndpoint'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_network', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client_network.NetworkEndpoint'>], '__doc__': u'Information about a single network connection.', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.NetworkConnection'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_network', '__doc__': u'A list of connections on the host.', 'rdf_type': <class 'grr_response_core.lib.rdfvalues.client_network.NetworkConnection'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_network', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFBytes'>], 'human_readable_address': <property object at 0x7fd0dd1494c8>, 'AsIPAddr': <function AsIPAddr at 0x7fd0dd14ded8>, '__doc__': u"A network address.\n\n  We'd prefer to use socket.inet_pton and  inet_ntop here, but they aren't\n  available on windows before python 3.4. So we use the older IPv4 functions for\n  v4 addresses and our own pure python implementations for IPv6.\n  ", 'protobuf': <class 'grr_response_proto.jobs_pb2.NetworkAddress'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_network', '__doc__': u'DNS client config.', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.DNSClientConfiguration'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_network', '__doc__': u'A MAC address.', 'human_readable_address': <property object at 0x7fd0dd149998>}
{'GetIPAddresses': <function GetIPAddresses at 0x7fd0dd15c0c8>, '__module__': 'grr_response_core.lib.rdfvalues.client_network', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client_network.MacAddress'>, <class 'grr_response_core.lib.rdfvalues.client_network.NetworkAddress'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetime'>], '__doc__': u'A network interface on the client system.', 'protobuf': <class 'grr_response_proto.jobs_pb2.Interface'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_network', 'GetIPAddresses': <function GetIPAddresses at 0x7fd0dd1625f0>, '__doc__': u'The list of interfaces on a host.', 'rdf_type': <class 'grr_response_core.lib.rdfvalues.client_network.Interface'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', 'FromPrivateKey': <classmethod object at 0x7fd0dd15fbb0>, 'Add': <function Add at 0x7fd0dd1110c8>, 'Queue': <function Queue at 0x7fd0dd111140>, 'ParseFromUnicode': <function ParseFromUnicode at 0x7fd0dd10fe60>, 'CLIENT_ID_RE': <_sre.SRE_Pattern object at 0x7fd0e10338d0>, 'Validate': <classmethod object at 0x7fd0dd15f9b8>, '__doc__': u'A client urn has to have a specific form.', '__init__': <function __init__ at 0x7fd0dd10fde8>, 'FromPublicKey': <classmethod object at 0x7fd0dd15fb08>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', '__doc__': u'A PCI device on the client.\n\n  This class describes a PCI device located on the client.\n  ', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.PCIDevice'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', '__doc__': u'Description of the configured repositories (Yum etc).\n\n  Describes the configured software package repositories.\n  ', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.PackageRepository'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>], '__doc__': u'Description of the running management agent (puppet etc).\n\n  Describes the state, last run timestamp, and name of the management agent\n  installed on the system.\n  ', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.ManagementAgent'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', '__doc__': u'Information about password structures.', 'protobuf': <class 'grr_response_proto.knowledge_base_pb2.PwEntry'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client.PwEntry'>], '__doc__': u'Information about system posix groups.', 'protobuf': <class 'grr_response_proto.knowledge_base_pb2.Group'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client.PwEntry'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetime'>], '__doc__': u'Information about the users.', '__init__': <function __init__ at 0x7fd0dd129938>, 'protobuf': <class 'grr_response_proto.knowledge_base_pb2.User'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', '__doc__': u'Backwards compatibility for old clients.\n\n  Linux client action EnumerateUsers previously returned KnowledgeBaseUser\n  objects.\n  '}
{'__module__': 'grr_response_core.lib.rdfvalues.client', '_CreateNewUser': <function _CreateNewUser at 0x7fd0dd137848>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client.User'>], 'GetUser': <function GetUser at 0x7fd0dd137938>, 'MergeOrAddUser': <function MergeOrAddUser at 0x7fd0dd1378c0>, 'GetKbFieldNames': <function GetKbFieldNames at 0x7fd0dd1379b0>, '__doc__': u'Information about the system and users.', 'protobuf': <class 'grr_response_proto.knowledge_base_pb2.KnowledgeBase'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', '__doc__': u'Various hardware information.', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.HardwareInfo'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', '__doc__': u'The GRR client information.', 'protobuf': <class 'grr_response_proto.jobs_pb2.ClientInformation'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>], '__eq__': <function __eq__ at 0x7fd0dd0d5cf8>, '__doc__': u'Stores information about a buffer in a file on the client.', 'protobuf': <class 'grr_response_proto.jobs_pb2.BufferReference'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client_network.NetworkConnection'>], 'FromPsutilProcess': <classmethod object at 0x7fd0dd0d77c0>, '__doc__': u'Represent a process on the client.', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.Process'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', '__doc__': u'Represent an installed package on the client.', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.SoftwarePackage'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', '__doc__': u'A list of installed packages on the system.', 'rdf_type': <class 'grr_response_core.lib.rdfvalues.client.SoftwarePackage'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', '__doc__': u'A log message sent from the client to the server.', 'protobuf': <class 'grr_response_proto.jobs_pb2.LogMessage'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>], 'FromCurrentSystem': <classmethod object at 0x7fd0dd0f35c8>, 'signature': <function signature at 0x7fd0dd0f6938>, 'arch': <property object at 0x7fd0dd0ef730>, '__doc__': u'A protobuf to represent the current system.', 'protobuf': <class 'grr_response_proto.jobs_pb2.Uname'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', 'protobuf': <class 'grr_response_proto.jobs_pb2.StartupInfo'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client.ClientInformation'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetime'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.client', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.Dict'>, <class 'grr_response_core.lib.rdfvalues.client_fs.StatEntry'>], '__doc__': u'Windows Service.', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.WindowsServiceInformation'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFURN'>], '__doc__': u'OSX Service (launchagent/daemon).', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.OSXServiceInformation'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.AttributedDict'>, <class 'grr_response_core.lib.rdfvalues.client.SoftwarePackage'>, <class 'grr_response_core.lib.rdfvalues.client_fs.StatEntry'>], '__doc__': u'Linux Service (init/upstart/systemd).', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.LinuxServiceInformation'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.RunKey'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', '__doc__': u'Structure of a Run Key entry with keyname, filepath, and last written.', 'rdf_type': <class 'grr_response_core.lib.rdfvalues.client.RunKey'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client.ClientInformation'>, <class 'grr_response_core.lib.rdfvalues.client.ClientURN'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetime'>, <class 'grr_response_core.lib.rdfvalue.SessionID'>], '__doc__': u'Details of a client crash.', 'protobuf': <class 'grr_response_proto.jobs_pb2.ClientCrash'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client.ClientInformation'>, <class 'grr_response_core.lib.rdfvalues.client.ClientURN'>, <class 'grr_response_core.lib.rdfvalues.client_network.Interface'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetime'>, <class 'grr_response_core.lib.rdfvalues.client.Uname'>, <class 'grr_response_core.lib.rdfvalues.client.User'>], '__doc__': u"Object containing client's summary data.", 'protobuf': <class 'grr_response_proto.jobs_pb2.ClientSummary'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client', 'versions': <property object at 0x7fd0dd043158>}
{'FromString': <function FromString at 0x7fd0dcffe2a8>, '__module__': 'grr_response_core.config.build', 'Validate': <function Validate at 0x7fd0dcffe230>, '__doc__': u'A path to a file or a directory.', '__init__': <function __init__ at 0x7fd0dcffe1b8>}
{'__module__': 'grr_response_core.lib.rdfvalues.config', 'protobuf': <class 'grr_response_proto.config_pb2.AdminUIClientWarningRule'>}
{'__module__': 'grr_response_core.lib.rdfvalues.config', 'protobuf': <class 'grr_response_proto.config_pb2.AdminUIClientWarningsConfigOption'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.config.AdminUIClientWarningRule'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.client_stats', '__doc__': 'CPU usage is reported as both a system and user components.', 'protobuf': <class 'grr_response_proto.jobs_pb2.CpuSeconds'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_stats', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>], '__doc__': 'A single CPU sample.', 'FromMany': <classmethod object at 0x7fd0dcf8f2b8>, 'protobuf': <class 'grr_response_proto.jobs_pb2.CpuSample'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_stats', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>], '__doc__': 'A single I/O sample as collected by `psutil`.', 'FromMany': <classmethod object at 0x7fd0dcf8f670>, 'protobuf': <class 'grr_response_proto.jobs_pb2.IOSample'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_stats', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client_stats.CpuSample'>, <class 'grr_response_core.lib.rdfvalues.client_stats.IOSample'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetime'>], 'Downsampled': <classmethod object at 0x7fd0dcf8fa60>, 'DEFAULT_SAMPLING_INTERVAL': <Duration('1m')>, '__doc__': 'A client stat object.', '_Downsample': <classmethod object at 0x7fd0dcf8fa98>, 'protobuf': <class 'grr_response_proto.jobs_pb2.ClientStats'>}
{'__module__': 'grr_response_core.lib.rdfvalues.client_stats', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client.ClientURN'>, <class 'grr_response_core.lib.rdfvalues.client_stats.CpuSeconds'>, <class 'grr_response_core.lib.rdfvalue.SessionID'>], '__doc__': 'An RDFValue class representing the client resource usage.', 'protobuf': <class 'grr_response_proto.jobs_pb2.ClientResources'>}
{'HasTaskID': <function HasTaskID at 0x7fd0dcf8a9b0>, '__module__': 'grr_response_core.lib.rdfvalues.flows', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.EmbeddedRDFValue'>, <class 'grr_response_core.lib.rdfvalue.FlowSessionID'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetime'>, <class 'grr_response_core.lib.rdfvalue.RDFURN'>], 'task_id': <property object at 0x7fd0dcf82520>, 'lock': <thread.lock object at 0x7fd0dcfe13d0>, 'args': <property object at 0x7fd0dcf82680>, 'ClearPayload': <function ClearPayload at 0x7fd0dcfa4a28>, 'payload': <property object at 0x7fd0dcf98890>, 'next_id_base': 0, 'GenerateTaskID': <function GenerateTaskID at 0x7fd0dcf8a500>, 'max_ttl': 5, '__doc__': u'An RDFValue class to manage GRR messages.', '__init__': <function __init__ at 0x7fd0dcf8a230>, 'protobuf': <class 'grr_response_proto.jobs_pb2.GrrMessage'>}
{'__module__': 'grr_response_core.lib.rdfvalues.flows', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client_stats.CpuSeconds'>, <class 'grr_response_core.lib.rdfvalue.SessionID'>], '__doc__': u'The client status message.\n\n  When the client responds to a request, it sends a series of response messages,\n  followed by a single status message. The GrrStatus message contains error and\n  traceback information for any failures on the client.\n  ', 'protobuf': <class 'grr_response_proto.jobs_pb2.GrrStatus'>}
{'__module__': 'grr_response_core.lib.rdfvalues.flows', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>, <class 'grr_response_core.lib.rdfvalue.SessionID'>], '__doc__': u'A flow notification.', 'protobuf': <class 'grr_response_proto.jobs_pb2.GrrNotification'>}
{'__module__': 'grr_response_core.lib.rdfvalues.flows', 'protobuf': <class 'grr_response_proto.flows_pb2.FlowProcessingRequest'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>]}
{'notification_types': [u'Discovery', u'ViewObject', u'FlowStatus', u'GrantAccess', u'ArchiveGenerationFinished', u'Error'], '__module__': 'grr_response_core.lib.rdfvalues.flows', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>, <class 'grr_response_core.lib.rdfvalue.RDFURN'>], '__doc__': u'A notification is used in the GUI to alert users.\n\n  Usually the notification means that some operation is completed, and provides\n  a link to view the results.\n  ', 'protobuf': <class 'grr_response_proto.jobs_pb2.Notification'>}
{'__module__': 'grr_response_core.lib.rdfvalues.flows', 'protobuf': <class 'grr_response_proto.jobs_pb2.FlowNotification'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client.ClientURN'>, <class 'grr_response_core.lib.rdfvalue.SessionID'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.flows', '__doc__': u'A List of notifications for this user.', 'rdf_type': <class 'grr_response_core.lib.rdfvalues.flows.Notification'>}
{'__module__': 'grr_response_core.lib.rdfvalues.flows', 'protobuf': <class 'grr_response_proto.jobs_pb2.PackedMessageList'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>, <class 'grr_response_core.lib.rdfvalue.RDFURN'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.flows', 'protobuf': <class 'grr_response_proto.jobs_pb2.MessageList'>, '__len__': <function __len__ at 0x7fd0dcf5c578>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.flows.GrrMessage'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.flows', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.crypto.EncryptionKey'>], 'GetCipher': <function GetCipher at 0x7fd0dcf5cb18>, 'GetHMAC': <function GetHMAC at 0x7fd0dcf5caa0>, 'GetInializedKeys': <classmethod object at 0x7fd0dcf54718>, '__doc__': u'Contains information about a cipher and keys.', 'protobuf': <class 'grr_response_proto.jobs_pb2.CipherProperties'>}
{'__module__': 'grr_response_core.lib.rdfvalues.flows', 'protobuf': <class 'grr_response_proto.jobs_pb2.CipherMetadata'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFURN'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.flows', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client.ClientURN'>, <class 'grr_response_core.lib.rdfvalue.RDFURN'>], '__doc__': u'An RDFValue class representing flow log entries.', 'protobuf': <class 'grr_response_proto.jobs_pb2.FlowLog'>}
{'__module__': 'grr_response_core.lib.rdfvalues.flows', 'protobuf': <class 'grr_response_proto.jobs_pb2.HttpRequest'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.flows', 'num_messages': 0, 'protobuf': <class 'grr_response_proto.jobs_pb2.ClientCommunication'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.crypto.EncryptionKey'>, <class 'grr_response_core.lib.rdfvalues.flows.HttpRequest'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.flows', 'protobuf': <class 'grr_response_proto.flows_pb2.ACLToken'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.stats', 'bins_heights': <property object at 0x7fd0dcf054c8>, 'protobuf': <class 'grr_response_proto.jobs_pb2.Distribution'>, 'Record': <function Record at 0x7fd0dcf0d0c8>, '__doc__': u'Statistics values for events - i.e. things that take time.', '__init__': <function __init__ at 0x7fd0dcf0d050>}
{'__module__': 'grr_response_core.lib.rdfvalues.stats', '__doc__': u'Metric field definition.', 'protobuf': <class 'grr_response_proto.jobs_pb2.MetricFieldDefinition'>}
{'DefaultValue': <function DefaultValue at 0x7fd0dcf122a8>, '__module__': 'grr_response_core.lib.rdfvalues.stats', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.stats.MetricFieldDefinition'>], '__doc__': u'Metric metadata for a particular metric.', 'protobuf': <class 'grr_response_proto.jobs_pb2.MetricMetadata'>}
{'__module__': 'grr_response_core.lib.rdfvalues.stats', 'protobuf': <class 'grr_response_proto.jobs_pb2.StatsHistogramBin'>}
{'__module__': 'grr_response_core.lib.rdfvalues.stats', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.stats.StatsHistogramBin'>], 'protobuf': <class 'grr_response_proto.jobs_pb2.StatsHistogram'>, 'FromBins': <classmethod object at 0x7fd0dcf220f8>, '__doc__': u'Histogram with a user-provided set of bins.', 'RegisterValue': <function RegisterValue at 0x7fd0dcf231b8>}
{'std': <property object at 0x7fd0dcf242b8>, '__module__': 'grr_response_core.lib.rdfvalues.stats', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.stats.StatsHistogram'>], 'protobuf': <class 'grr_response_proto.jobs_pb2.RunningStats'>, 'RegisterValue': <function RegisterValue at 0x7fd0dcf23668>, '__doc__': u'Class for collecting running stats: mean, stdev and histogram data.', 'mean': <property object at 0x7fd0dcf24260>}
{'__module__': 'grr_response_core.lib.rdfvalues.stats', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client_stats.ClientResources'>, <class 'grr_response_core.lib.rdfvalues.stats.RunningStats'>], 'RegisterResources': <function RegisterResources at 0x7fd0dcf28320>, '__init__': <function __init__ at 0x7fd0dcf28230>, 'NETWORK_STATS_BINS': [16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152], 'CPU_STATS_BINS': [0.1, 0.2, 0.3, 0.4, 0.5, 0.75, 1, 1.5, 2, 2.5, 3, 4, 5, 6, 7, 8, 9, 10, 15, 20], '__doc__': u"RDF value representing clients' resources usage statistics for hunts.", 'NUM_WORST_PERFORMERS': 10, 'protobuf': <class 'grr_response_proto.jobs_pb2.ClientResourcesStats'>}
{'__module__': 'grr_response_core.lib.rdfvalues.stats', '__doc__': u'A Graph sample is a single data point.', 'protobuf': <class 'grr_response_proto.analysis_pb2.Sample'>}
{'__module__': 'grr_response_core.lib.rdfvalues.stats', '__doc__': u'A Graph float data point.', 'protobuf': <class 'grr_response_proto.analysis_pb2.SampleFloat'>}
{'__module__': 'grr_response_core.lib.rdfvalues.stats', '__nonzero__': <function __nonzero__ at 0x7fd0dcf2eed8>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.stats.Sample'>], '__getitem__': <function __getitem__ at 0x7fd0dcf2ef50>, '__iter__': <function __iter__ at 0x7fd0dcf32050>, 'Append': <function Append at 0x7fd0dcf2ede8>, '__doc__': u'A Graph is a collection of sample points.', '__len__': <function __len__ at 0x7fd0dcf2ee60>, 'protobuf': <class 'grr_response_proto.analysis_pb2.Graph'>}
{'__module__': 'grr_response_core.lib.rdfvalues.stats', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.stats.SampleFloat'>], '__getitem__': <function __getitem__ at 0x7fd0dcf32e60>, '__iter__': <function __iter__ at 0x7fd0dcf32ed8>, '__doc__': u'A Graph that stores sample points as floats.', 'protobuf': <class 'grr_response_proto.analysis_pb2.GraphFloat'>}
{'__module__': 'grr_response_core.lib.rdfvalues.stats', '__doc__': u'A sequence of graphs (e.g. evolving over time).', 'rdf_type': <class 'grr_response_core.lib.rdfvalues.stats.Graph'>}
{'__module__': 'grr_response_core.lib.rdfvalues.stats', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.stats.Graph'>], '__doc__': u'A collection of graphs for a single client-report type.', 'protobuf': <class 'grr_response_proto.analysis_pb2.ClientGraphSeries'>}
{'__module__': 'grr_response_core.lib.rdfvalues.cloud', 'protobuf': <class 'grr_response_proto.flows_pb2.CloudMetadataRequest'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.Dict'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.cloud', 'protobuf': <class 'grr_response_proto.flows_pb2.CloudMetadataRequests'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.cloud.CloudMetadataRequest'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.cloud', 'protobuf': <class 'grr_response_proto.flows_pb2.CloudMetadataResponse'>}
{'__module__': 'grr_response_core.lib.rdfvalues.cloud', 'protobuf': <class 'grr_response_proto.flows_pb2.CloudMetadataResponses'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.cloud.CloudMetadataResponse'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.cloud', 'protobuf': <class 'grr_response_proto.jobs_pb2.GoogleCloudInstance'>}
{'__module__': 'grr_response_core.lib.rdfvalues.cloud', 'protobuf': <class 'grr_response_proto.jobs_pb2.AmazonCloudInstance'>}
{'__module__': 'grr_response_core.lib.rdfvalues.cloud', 'protobuf': <class 'grr_response_proto.jobs_pb2.CloudInstance'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.cloud.AmazonCloudInstance'>, <class 'grr_response_core.lib.rdfvalues.cloud.GoogleCloudInstance'>]}
{'__module__': 'grr_response_server.rdfvalues.objects', 'protobuf': <class 'grr_response_proto.objects_pb2.ClientLabel'>}
{'__module__': 'grr_response_server.rdfvalues.objects', 'protobuf': <class 'grr_response_proto.objects_pb2.StringMapEntry'>}
{'__module__': 'grr_response_server.rdfvalues.objects', 'GetMacAddresses': <function GetMacAddresses at 0x7fd0dce78050>, 'rdf_deps': [<class 'grr_response_server.rdfvalues.objects.StringMapEntry'>, <class 'grr_response_core.lib.rdfvalues.cloud.CloudInstance'>, <class 'grr_response_core.lib.rdfvalues.client_fs.Filesystem'>, <class 'grr_response_core.lib.rdfvalues.client.HardwareInfo'>, <class 'grr_response_core.lib.rdfvalues.client_network.Interface'>, <class 'grr_response_core.lib.rdfvalues.client.KnowledgeBase'>, <class 'grr_response_core.lib.rdfvalues.client.StartupInfo'>, <class 'grr_response_core.lib.rdfvalues.client_fs.Volume'>, <class 'grr_response_core.lib.rdfvalue.ByteSize'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetime'>], 'GetIPAddresses': <function GetIPAddresses at 0x7fd0dce780c8>, 'FromSerializedString': <classmethod object at 0x7fd0dcef61a0>, 'Uname': <function Uname at 0x7fd0dcef2f50>, 'GetSummary': <function GetSummary at 0x7fd0dce78140>, '__doc__': u'The client object.\n\n  Attributes:\n    timestamp: An rdfvalue.Datetime indicating when this client snapshot was\n      saved to the database. Should be present in every client object loaded\n      from the database, but is not serialized with the rdfvalue fields.\n  ', '__init__': <function __init__ at 0x7fd0dcef2e60>, 'protobuf': <class 'grr_response_proto.objects_pb2.ClientSnapshot'>}
{'__module__': 'grr_response_server.rdfvalues.objects', 'protobuf': <class 'grr_response_proto.objects_pb2.ClientMetadata'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client_network.NetworkAddress'>, <class 'grr_response_core.lib.rdfvalues.crypto.RDFX509Cert'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetime'>]}
{'GetLabelsNames': <function GetLabelsNames at 0x7fd0dce8a7d0>, '__module__': 'grr_response_server.rdfvalues.objects', 'rdf_deps': [<class 'grr_response_server.rdfvalues.objects.ClientMetadata'>, <class 'grr_response_server.rdfvalues.objects.ClientSnapshot'>, <class 'grr_response_server.rdfvalues.objects.ClientLabel'>, <class 'grr_response_core.lib.rdfvalues.client.StartupInfo'>], '__doc__': u'ClientFullInfo object.', 'protobuf': <class 'grr_response_proto.objects_pb2.ClientFullInfo'>}
{'__module__': 'grr_response_server.rdfvalues.objects', 'protobuf': <class 'grr_response_proto.objects_pb2.GRRUser'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.crypto.Password'>]}
{'__module__': 'grr_response_server.rdfvalues.objects', 'protobuf': <class 'grr_response_proto.objects_pb2.ApprovalGrant'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>]}
{'__module__': 'grr_response_server.rdfvalues.objects', 'is_expired': <property object at 0x7fd0dce89aa0>, 'protobuf': <class 'grr_response_proto.objects_pb2.ApprovalRequest'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>, <class 'grr_response_server.rdfvalues.objects.ApprovalGrant'>]}
{'FromBytes': <classmethod object at 0x7fd0dcea40c0>, 'AsBytes': <function AsBytes at 0x7fd0dcea3488>, '__module__': 'grr_response_server.rdfvalues.objects', 'AsHashDigest': <function AsHashDigest at 0x7fd0dcea3578>, 'hash_id_length': None, '__str__': <function __str__ at 0x7fd0dcea3668>, 'SerializeToString': <function SerializeToString at 0x7fd0dcea3398>, 'ParseFromString': <function ParseFromString at 0x7fd0dcea32a8>, 'ParseFromDatastore': <function ParseFromDatastore at 0x7fd0dcea3320>, 'data_store_type': u'bytes', '_HashID__abstract': True, '__lt__': <function __lt__ at 0x7fd0dcea36e0>, 'AsHexString': <function AsHexString at 0x7fd0dcea3500>, '__eq__': <function __eq__ at 0x7fd0dcea3758>, '__doc__': u'An unique hash identifier.', '__init__': <function __init__ at 0x7fd0dcea3230>, '__repr__': <function __repr__ at 0x7fd0dcea35f0>}
{'hash_id_length': 32, '__module__': 'grr_response_server.rdfvalues.objects', 'FromComponents': <classmethod object at 0x7fd0dcea4168>, '__doc__': u'An unique path identifier corresponding to some path.\n\n  Args:\n    components: A list of path components to construct the identifier from.\n  '}
{'TSK': <classmethod object at 0x7fd0dcea4210>, '__module__': 'grr_response_server.rdfvalues.objects', 'PathTypeFromPathspecPathType': <classmethod object at 0x7fd0dcea4280>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>, <class 'grr_response_core.lib.rdfvalues.client_fs.StatEntry'>, <class 'grr_response_core.lib.rdfvalues.crypto.Hash'>], 'FromPathSpec': <classmethod object at 0x7fd0dcea42b8>, 'basename': <property object at 0x7fd0dcea5418>, 'GetParentPathID': <function GetParentPathID at 0x7fd0dcea8230>, 'GetParent': <function GetParent at 0x7fd0dcea82a8>, 'FromStatEntry': <classmethod object at 0x7fd0dcea42f0>, 'Registry': <classmethod object at 0x7fd0dcea4248>, 'UpdateFrom': <function UpdateFrom at 0x7fd0dcea8398>, 'root': <property object at 0x7fd0dcea53c0>, 'GetAncestors': <function GetAncestors at 0x7fd0dcea8320>, 'GetPathID': <function GetPathID at 0x7fd0dcea81b8>, 'OS': <classmethod object at 0x7fd0dcea41d8>, '__doc__': u'Basic metadata about a path which has been observed on a client.', '__init__': <function __init__ at 0x7fd0dcea3f50>, 'protobuf': <class 'grr_response_proto.objects_pb2.PathInfo'>}
{'__module__': 'grr_response_server.rdfvalues.objects', 'protobuf': <class 'grr_response_proto.objects_pb2.ClientReference'>, 'rdf_deps': []}
{'ToHuntURN': <function ToHuntURN at 0x7fd0dceb1e60>, '__module__': 'grr_response_server.rdfvalues.objects', 'protobuf': <class 'grr_response_proto.objects_pb2.HuntReference'>, 'rdf_deps': []}
{'__module__': 'grr_response_server.rdfvalues.objects', 'protobuf': <class 'grr_response_proto.objects_pb2.CronJobReference'>, 'rdf_deps': []}
{'ToFlowURN': <function ToFlowURN at 0x7fd0dceb77d0>, '__module__': 'grr_response_server.rdfvalues.objects', 'protobuf': <class 'grr_response_proto.objects_pb2.FlowReference'>, 'rdf_deps': []}
{'ToPath': <function ToPath at 0x7fd0dceb7ed8>, '__module__': 'grr_response_server.rdfvalues.objects', 'rdf_deps': [], 'ToURN': <function ToURN at 0x7fd0dceb7e60>, '__doc__': u'Object reference pointing to a VFS file.', 'protobuf': <class 'grr_response_proto.objects_pb2.VfsFileReference'>}
{'__module__': 'grr_response_server.rdfvalues.objects', 'protobuf': <class 'grr_response_proto.objects_pb2.ApprovalRequestReference'>, 'rdf_deps': []}
{'__module__': 'grr_response_server.rdfvalues.objects', 'protobuf': <class 'grr_response_proto.objects_pb2.ObjectReference'>, 'rdf_deps': [<class 'grr_response_server.rdfvalues.objects.ClientReference'>, <class 'grr_response_server.rdfvalues.objects.HuntReference'>, <class 'grr_response_server.rdfvalues.objects.CronJobReference'>, <class 'grr_response_server.rdfvalues.objects.FlowReference'>, <class 'grr_response_server.rdfvalues.objects.VfsFileReference'>, <class 'grr_response_server.rdfvalues.objects.ApprovalRequestReference'>]}
{'__module__': 'grr_response_server.rdfvalues.objects', 'protobuf': <class 'grr_response_proto.objects_pb2.UserNotification'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>, <class 'grr_response_server.rdfvalues.objects.ObjectReference'>]}
{'__module__': 'grr_response_server.rdfvalues.objects', 'protobuf': <class 'grr_response_proto.objects_pb2.MessageHandlerRequest'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>, <class 'grr_response_core.lib.rdfvalues.protodict.EmbeddedRDFValue'>]}
{'FromData': <classmethod object at 0x7fd0dce5c478>, 'hash_id_length': 32, '__module__': 'grr_response_server.rdfvalues.objects', '__doc__': u'SHA-256 based hash id.'}
{'hash_id_length': 32, '__module__': 'grr_response_server.rdfvalues.objects', '__doc__': u'Blob identificator.', 'FromBlobData': <classmethod object at 0x7fd0dce5c4b0>}
{'__module__': 'grr_response_server.rdfvalues.objects', 'protobuf': <class 'grr_response_proto.objects_pb2.ClientPathID'>, 'rdf_deps': [<class 'grr_response_server.rdfvalues.objects.PathID'>]}
{'__module__': 'grr_response_server.rdfvalues.objects', 'protobuf': <class 'grr_response_proto.objects_pb2.BlobReference'>, 'rdf_deps': [<class 'grr_response_server.rdfvalues.objects.BlobID'>]}
{'__module__': 'grr_response_server.rdfvalues.objects', 'protobuf': <class 'grr_response_proto.objects_pb2.BlobReferences'>, 'rdf_deps': [<class 'grr_response_server.rdfvalues.objects.BlobReference'>]}
{'__module__': 'grr_response_server.rdfvalues.objects', 'rdf_deps': [], '__doc__': u"Class used to represent objects that can't be deserialized properly.\n\n  When deserializing certain objects stored in the database (FlowResults, for\n  example), we don't want to fail hard if for some reason the type of the value\n  is unknown and can no longer be found in the system. When this happens,\n  SerializedValueOfUnrecognizedType is used as a stub. This way, affected\n  API calls won't simply fail and raise, but will rather return all the results\n  they can and the user will be able to fetch the data, albeit in serialized\n  form.\n  ", 'protobuf': <class 'grr_response_proto.objects_pb2.SerializedValueOfUnrecognizedType'>}
{'__module__': 'grr_response_server.rdfvalues.objects', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>], '_HTTP_STATUS_TO_CODE': {200: 1, 500: 2, 403: 3, 404: 4, 501: 5}, 'FromHttpRequestResponse': <classmethod object at 0x7fd0dce5cc20>, '__doc__': u'Audit entry for API calls, persistend in the relational database.', 'protobuf': <class 'grr_response_proto.objects_pb2.APIAuditEntry'>}
{'__module__': 'grr_response_server.rdfvalues.objects', 'protobuf': <class 'grr_response_proto.objects_pb2.SignedBinaryID'>}
{'__module__': 'grr_response_core.lib.rdfvalues.artifacts', '_ValidateType': <function _ValidateType at 0x7fd0dcdd85f0>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.Dict'>], '_ValidatePaths': <function _ValidatePaths at 0x7fd0dcdd8578>, '_ValidateCommandArgs': <function _ValidateCommandArgs at 0x7fd0dcdd8488>, '_ValidateRequiredAttributes': <function _ValidateRequiredAttributes at 0x7fd0dcdd8668>, 'TYPE_MAP': {1: {u'output_type': u'StatEntry', u'required_attributes': [u'paths']}, 2: {u'output_type': u'StatEntry', u'required_attributes': [u'keys']}, 3: {u'output_type': u'RDFString', u'required_attributes': [u'key_value_pairs']}, 4: {u'output_type': u'Dict', u'required_attributes': [u'query']}, 5: {u'output_type': u'Undefined', u'required_attributes': [u'names']}, 6: {u'output_type': u'StatEntry', u'required_attributes': [u'paths']}, 7: {u'output_type': u'StatEntry', u'required_attributes': [u'paths']}, 8: {u'output_type': u'Undefined', u'required_attributes': [u'names']}, 40: {u'output_type': u'Undefined', u'required_attributes': [u'client_action']}, 41: {u'output_type': u'StatEntry', u'required_attributes': [u'paths']}, 42: {u'output_type': u'StatEntry', u'required_attributes': [u'artifact_list']}, 43: {u'output_type': u'BufferReference', u'required_attributes': [u'paths', u'content_regex_list']}, 45: {u'output_type': u'ExecuteResponse', u'required_attributes': [u'cmd', u'args']}, 46: {u'output_type': u'RekallResponse', u'required_attributes': [u'plugin']}}, '_ValidateReturnedTypes': <function _ValidateReturnedTypes at 0x7fd0dcdd8500>, 'OUTPUT_UNDEFINED': u'Undefined', 'Validate': <function Validate at 0x7fd0dcdd8410>, '__doc__': u'An ArtifactSource.', '__init__': <function __init__ at 0x7fd0dcdd8398>, 'protobuf': <class 'grr_response_proto.artifact_pb2.ArtifactSource'>}
{'__module__': 'grr_response_core.lib.rdfvalues.artifacts'}
{'ToYaml': <function ToYaml at 0x7fd0dcde1d70>, '__module__': 'grr_response_core.lib.rdfvalues.artifacts', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.artifacts.ArtifactName'>, <class 'grr_response_core.lib.rdfvalues.artifacts.ArtifactSource'>], 'SUPPORTED_OS_LIST': [u'Windows', u'Linux', u'Darwin'], 'ToPrimitiveDict': <function ToPrimitiveDict at 0x7fd0dcde1cf8>, 'required_repeated_fields': [u'conditions', u'labels', u'supported_os', u'urls', u'provides'], 'ARTIFACT_LABELS': {u'Configuration Files': u'Configuration files artifacts.', u'Network': u'Describe networking state.', u'System': u'Core system artifacts.', u'Authentication': u'Authentication artifacts.', u'Memory': u'Artifacts retrieved from Memory.', u'Mail': u'Mail client applications artifacts.', u'External Media': u'Contain external media data / events e.g. USB drives.', u'Users': u'Information about users.', u'Antivirus': u'Antivirus related artifacts, e.g. quarantine files.', u'Browser': u'Web Browser artifacts.', u'KnowledgeBase': u'Artifacts used in knowledgebase generation.', u'Execution': u'Contain execution events.', u'Processes': u'Describe running processes.', u'ExternalAccount': u"Information about any users' account, e.g. username, account ID, etc.", u'iOS': u'Artifacts related to iOS devices connected to the system.', u'Hadoop': u'Hadoop artifacts.', u'Rekall': u'Artifacts using the Rekall memory forensics framework.', u'IM': u'Instant Messaging / Chat applications artifacts.', u'Docker': u'Docker artifacts.', u'Cloud Storage': u'Cloud Storage artifacts.', u'Software': u'Installed software.', u'Logs': u'Contain log files.', u'History Files': u'History files artifacts e.g. .bash_history.', u'Cloud': u'Cloud applications artifacts.'}, 'ToDict': <function ToDict at 0x7fd0dcde1c80>, 'ToJson': <function ToJson at 0x7fd0dcde1c08>, '__doc__': u'An RDFValue representation of an artifact.', 'protobuf': <class 'grr_response_proto.artifact_pb2.Artifact'>}
{'__module__': 'grr_response_core.lib.rdfvalues.artifacts', '__doc__': u'Describes artifact processor.', 'protobuf': <class 'grr_response_proto.artifact_pb2.ArtifactProcessorDescriptor'>}
{'__module__': 'grr_response_core.lib.rdfvalues.artifacts', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.artifacts.Artifact'>, <class 'grr_response_core.lib.rdfvalues.artifacts.ArtifactProcessorDescriptor'>], '__doc__': u'Includes artifact, its JSON source, processors and additional info.', 'protobuf': <class 'grr_response_proto.artifact_pb2.ArtifactDescriptor'>}
{'__module__': 'grr_response_core.lib.rdfvalues.artifacts', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.artifacts.ArtifactSource'>, <class 'grr_response_core.lib.rdfvalue.ByteSize'>, u'ExpandedSource'], '__doc__': u'An RDFValue representing a source and everything it depends on.', 'protobuf': <class 'grr_response_proto.artifact_pb2.ExpandedSource'>}
{'__module__': 'grr_response_core.lib.rdfvalues.artifacts', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.artifacts.ExpandedSource'>, <class 'grr_response_core.lib.rdfvalues.artifacts.ArtifactName'>], '__doc__': u'An RDFValue representing an artifact with its extended sources.', 'protobuf': <class 'grr_response_proto.artifact_pb2.ExpandedArtifact'>}
{'__module__': 'grr_response_core.lib.rdfvalues.artifacts', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.artifacts.ArtifactName'>, <class 'grr_response_core.lib.rdfvalue.ByteSize'>, <class 'grr_response_core.lib.rdfvalues.client.KnowledgeBase'>], 'path_type': <property object at 0x7fd0dcb70208>, 'Validate': <function Validate at 0x7fd0dcb6ef50>, '__doc__': u'Arguments for the artifact collector flow.', 'protobuf': <class 'grr_response_proto.flows_pb2.ArtifactCollectorFlowArgs'>}
{'__module__': 'grr_response_core.lib.rdfvalues.artifacts', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.artifacts.ExpandedArtifact'>, <class 'grr_response_core.lib.rdfvalues.client.KnowledgeBase'>, <class 'grr_response_core.lib.rdfvalue.ByteSize'>], '__doc__': u'An RDFValue representation of an artifact bundle.', 'protobuf': <class 'grr_response_proto.artifact_pb2.ClientArtifactCollectorArgs'>}
{'GetValueClass': <function GetValueClass at 0x7fd0dcb87578>, '__module__': 'grr_response_core.lib.rdfvalues.artifacts', '__doc__': u'An RDFValue representing one type of response for a client action.', 'protobuf': <class 'grr_response_proto.artifact_pb2.ClientActionResult'>}
{'__module__': 'grr_response_core.lib.rdfvalues.artifacts', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.artifacts.ArtifactName'>, <class 'grr_response_core.lib.rdfvalues.artifacts.ClientActionResult'>], '__doc__': u'An RDFValue representation of a single collected artifact.', 'protobuf': <class 'grr_response_proto.artifact_pb2.CollectedArtifact'>}
{'__module__': 'grr_response_core.lib.rdfvalues.artifacts', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.artifacts.CollectedArtifact'>, <class 'grr_response_core.lib.rdfvalues.client.KnowledgeBase'>], '__doc__': u'An RDFValue representation of the result of the collection results.', 'protobuf': <class 'grr_response_proto.artifact_pb2.ClientArtifactCollectorResult'>}
{'Evaluate': <function Evaluate at 0x7fd0dcb8fa28>, '__module__': 'grr_response_server.foreman_rules', 'Validate': <function Validate at 0x7fd0dcb8faa0>, '__doc__': u'Abstract base class of foreman client rules.'}
{'Evaluate': <function Evaluate at 0x7fd0dcb8fc80>, '__module__': 'grr_response_server.foreman_rules', 'Validate': <function Validate at 0x7fd0dcb8fcf8>, '__doc__': u'This rule will fire if the client OS is marked as true in the proto.', 'protobuf': <class 'grr_response_proto.jobs_pb2.ForemanOsClientRule'>}
{'Evaluate': <function Evaluate at 0x7fd0dcb9b668>, '__module__': 'grr_response_server.foreman_rules', 'Validate': <function Validate at 0x7fd0dcb9b6e0>, '__doc__': u'This rule will fire if the client has the selected label.', 'protobuf': <class 'grr_response_proto.jobs_pb2.ForemanLabelClientRule'>}
{'__module__': 'grr_response_server.foreman_rules', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.standard.RegularExpression'>], 'Evaluate': <function Evaluate at 0x7fd0dcba50c8>, '_ResolveFieldAFF4': <function _ResolveFieldAFF4 at 0x7fd0dcb9bf50>, 'Validate': <function Validate at 0x7fd0dcba5140>, '_ResolveField': <function _ResolveField at 0x7fd0dcba5050>, '__doc__': u'The Foreman schedules flows based on these rules firing.', 'protobuf': <class 'grr_response_proto.jobs_pb2.ForemanRegexClientRule'>}
{'__module__': 'grr_response_server.foreman_rules', 'rdf_deps': [], 'Evaluate': <function Evaluate at 0x7fd0dcba5ed8>, '_ResolveFieldAFF4': <function _ResolveFieldAFF4 at 0x7fd0dcba5de8>, 'Validate': <function Validate at 0x7fd0dcba5f50>, '_ResolveField': <function _ResolveField at 0x7fd0dcba5e60>, '__doc__': u'This rule will fire if the expression operator(attribute, value) is true.\n  ', 'protobuf': <class 'grr_response_proto.jobs_pb2.ForemanIntegerClientRule'>}
{'__module__': 'grr_response_server.foreman_rules', 'protobuf': <class 'grr_response_proto.jobs_pb2.ForemanRuleAction'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.Dict'>, <class 'grr_response_core.lib.rdfvalue.SessionID'>]}
{'__module__': 'grr_response_server.foreman_rules', 'rdf_deps': [<class 'grr_response_server.foreman_rules.ForemanIntegerClientRule'>, <class 'grr_response_server.foreman_rules.ForemanLabelClientRule'>, <class 'grr_response_server.foreman_rules.ForemanOsClientRule'>, <class 'grr_response_server.foreman_rules.ForemanRegexClientRule'>], 'Evaluate': <function Evaluate at 0x7fd0dcb358c0>, 'Validate': <function Validate at 0x7fd0dcb35938>, '__doc__': u'"Base class" proto for foreman client rule protos.', 'protobuf': <class 'grr_response_proto.jobs_pb2.ForemanClientRule'>}
{'__module__': 'grr_response_server.foreman_rules', 'rdf_deps': [<class 'grr_response_server.foreman_rules.ForemanClientRule'>], 'Evaluate': <function Evaluate at 0x7fd0dcb3c7d0>, 'Validate': <function Validate at 0x7fd0dcb3c848>, '__doc__': u'This proto holds rules and the strategy used to evaluate them.', 'protobuf': <class 'grr_response_proto.jobs_pb2.ForemanClientRuleSet'>}
{'__module__': 'grr_response_server.foreman_rules', 'rdf_deps': [<class 'grr_response_server.foreman_rules.ForemanClientRuleSet'>, <class 'grr_response_server.foreman_rules.ForemanRuleAction'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetime'>], 'GetLifetime': <function GetLifetime at 0x7fd0dcb42140>, 'Validate': <function Validate at 0x7fd0dcb42050>, '__doc__': u'A Foreman rule RDF value.', 'hunt_id': <property object at 0x7fd0dcb347e0>, 'protobuf': <class 'grr_response_proto.jobs_pb2.ForemanRule'>}
{'__module__': 'grr_response_server.foreman_rules', 'rdf_deps': [<class 'grr_response_server.foreman_rules.ForemanClientRuleSet'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetime'>], 'Evaluate': <function Evaluate at 0x7fd0dcb42de8>, 'GetLifetime': <function GetLifetime at 0x7fd0dcb42e60>, 'Validate': <function Validate at 0x7fd0dcb42d70>, '__doc__': u'A ForemanCondition RDF value.', 'protobuf': <class 'grr_response_proto.jobs_pb2.ForemanCondition'>}
{'__module__': 'grr_response_server.foreman_rules', '__doc__': u'A list of rules that the foreman will apply.', 'rdf_type': <class 'grr_response_server.foreman_rules.ForemanRule'>}
{'__module__': 'grr_response_server.rdfvalues.flow_runner', 'protobuf': <class 'grr_response_proto.jobs_pb2.RequestState'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client.ClientURN'>, <class 'grr_response_core.lib.rdfvalues.protodict.Dict'>, <class 'grr_response_core.lib.rdfvalues.flows.GrrMessage'>, <class 'grr_response_core.lib.rdfvalues.flows.GrrStatus'>, <class 'grr_response_core.lib.rdfvalue.SessionID'>]}
{'__module__': 'grr_response_server.rdfvalues.flow_runner', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client.ClientURN'>, <class 'grr_response_server.rdfvalues.objects.FlowReference'>, u'OutputPluginDescriptor', <class 'grr_response_core.lib.rdfvalue.RDFURN'>, <class 'grr_response_server.rdfvalues.flow_runner.RequestState'>], '__doc__': u'The argument to the flow runner.\n\n  Note that all flows receive these arguments. This object is stored in the\n  flows state.context.arg attribute.\n  ', 'protobuf': <class 'grr_response_proto.flows_pb2.FlowRunnerArgs'>}
{'__module__': 'grr_response_server.rdfvalues.flow_runner', 'Log': <function Log at 0x7fd0dcb67140>, 'protobuf': <class 'grr_response_proto.output_plugin_pb2.OutputPluginState'>, 'GetPlugin': <function GetPlugin at 0x7fd0dcb670c8>, 'Error': <function Error at 0x7fd0dcb671b8>, '__doc__': u'The output plugin state.', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.AttributedDict'>, u'OutputPluginDescriptor']}
{'__module__': 'grr_response_server.rdfvalues.flow_runner', 'protobuf': <class 'grr_response_proto.flows_pb2.FlowContext'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client_stats.ClientResources'>, <class 'grr_response_server.rdfvalues.flow_runner.OutputPluginState'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetime'>, <class 'grr_response_core.lib.rdfvalue.SessionID'>]}
{'__module__': 'grr_response_server.rdfvalues.output_plugin', 'protobuf': <class 'grr_response_proto.output_plugin_pb2.OutputPluginDescriptor'>, 'GetPluginArgsClass': <function GetPluginArgsClass at 0x7fd0dcaf2b90>, '__str__': <function __str__ at 0x7fd0dcaf2c80>, 'GetPlugin': <function GetPlugin at 0x7fd0dcaf2c08>, 'GetPluginClass': <function GetPluginClass at 0x7fd0dcaf2b18>, '__doc__': u'An rdfvalue describing the output plugin to create.'}
{'__module__': 'grr_response_server.rdfvalues.hunts', 'protobuf': <class 'grr_response_proto.jobs_pb2.HuntNotification'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client.ClientURN'>, <class 'grr_response_core.lib.rdfvalue.SessionID'>]}
{'__module__': 'grr_response_server.rdfvalues.hunts', 'protobuf': <class 'grr_response_proto.flows_pb2.HuntContext'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client_stats.ClientResources'>, <class 'grr_response_core.lib.rdfvalues.stats.ClientResourcesStats'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetime'>, <class 'grr_response_core.lib.rdfvalue.SessionID'>]}
{'FromHuntId': <classmethod object at 0x7fd0dcb064e8>, 'rdf_deps': [<class 'grr_response_server.rdfvalues.objects.FlowReference'>, <class 'grr_response_server.rdfvalues.objects.HuntReference'>], '__module__': 'grr_response_server.rdfvalues.hunts', 'FromFlowIdAndClientId': <classmethod object at 0x7fd0dcb06520>, '__doc__': u'A reference to a flow or a hunt.', 'protobuf': <class 'grr_response_proto.flows_pb2.FlowLikeObjectReference'>}
{'__module__': 'grr_response_server.rdfvalues.hunts', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.Duration'>, <class 'grr_response_server.foreman_rules.ForemanClientRuleSet'>, <class 'grr_response_server.rdfvalues.output_plugin.OutputPluginDescriptor'>, <class 'grr_response_core.lib.rdfvalue.RDFURN'>, <class 'grr_response_server.rdfvalues.hunts.FlowLikeObjectReference'>], 'Validate': <function Validate at 0x7fd0dcb09a28>, '__doc__': u'Hunt runner arguments definition.', '__init__': <function __init__ at 0x7fd0dcb099b0>, 'protobuf': <class 'grr_response_proto.flows_pb2.HuntRunnerArgs'>}
{'__module__': 'grr_response_server.rdfvalues.hunts', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client.ClientURN'>], '__doc__': u'An RDFValue class representing a hunt error.', 'protobuf': <class 'grr_response_proto.jobs_pb2.HuntError'>}
{'__module__': 'grr_response_server.rdfvalues.hunts', 'rdf_deps': [<class 'grr_response_server.rdfvalues.flow_runner.FlowRunnerArgs'>, <class 'grr_response_server.rdfvalues.output_plugin.OutputPluginDescriptor'>], 'GetFlowArgsClass': <function GetFlowArgsClass at 0x7fd0dcb1ab90>, 'Validate': <function Validate at 0x7fd0dcb1ab18>, '__doc__': u'Arguments to the generic hunt.', 'protobuf': <class 'grr_response_proto.flows_pb2.GenericHuntArgs'>}
{'__module__': 'grr_response_server.rdfvalues.hunts', 'protobuf': <class 'grr_response_proto.flows_pb2.CreateGenericHuntFlowArgs'>, 'rdf_deps': [<class 'grr_response_server.rdfvalues.hunts.GenericHuntArgs'>, <class 'grr_response_server.rdfvalues.hunts.HuntRunnerArgs'>]}
{'__module__': 'grr_response_server.rdfvalues.cronjobs', 'protobuf': <class 'grr_response_proto.jobs_pb2.CronJobRunStatus'>}
{'GetFlowArgsClass': <function GetFlowArgsClass at 0x7fd0dcaa8050>, '__module__': 'grr_response_server.rdfvalues.cronjobs', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.Duration'>, <class 'grr_response_server.rdfvalues.flow_runner.FlowRunnerArgs'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetime'>], '__doc__': u'Args to create a run for a cron job.', 'protobuf': <class 'grr_response_proto.flows_pb2.CreateCronJobFlowArgs'>}
{'__module__': 'grr_response_server.rdfvalues.cronjobs', 'protobuf': <class 'grr_response_proto.flows_pb2.SystemCronAction'>, 'rdf_deps': []}
{'GetFlowArgsClass': <function GetFlowArgsClass at 0x7fd0dcaad500>, '__module__': 'grr_response_server.rdfvalues.cronjobs', 'rdf_deps': [<class 'grr_response_server.rdfvalues.hunts.HuntRunnerArgs'>], '__doc__': u'Cron Action that starts a hunt.', 'protobuf': <class 'grr_response_proto.flows_pb2.HuntCronAction'>}
{'__module__': 'grr_response_server.rdfvalues.cronjobs', 'protobuf': <class 'grr_response_proto.flows_pb2.CronJobAction'>, 'rdf_deps': [<class 'grr_response_server.rdfvalues.cronjobs.SystemCronAction'>, <class 'grr_response_server.rdfvalues.cronjobs.HuntCronAction'>]}
{'__module__': 'grr_response_server.rdfvalues.cronjobs', 'rdf_deps': [<class 'grr_response_server.rdfvalues.cronjobs.CronJobAction'>, <class 'grr_response_core.lib.rdfvalues.protodict.AttributedDict'>, <class 'grr_response_core.lib.rdfvalue.Duration'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetime'>], '__doc__': u'The cron job class.', '__init__': <function __init__ at 0x7fd0dcab6758>, 'protobuf': <class 'grr_response_proto.flows_pb2.CronJob'>}
{'__module__': 'grr_response_server.rdfvalues.cronjobs', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>], '__doc__': u'A single run of a cron job.', 'GenerateRunId': <function GenerateRunId at 0x7fd0dcac35f0>, 'protobuf': <class 'grr_response_proto.flows_pb2.CronJobRun'>}
{'__module__': 'grr_response_server.rdfvalues.cronjobs', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.Duration'>, <class 'grr_response_server.rdfvalues.hunts.HuntRunnerArgs'>], 'GetFlowArgsClass': <function GetFlowArgsClass at 0x7fd0dcacb668>, 'FromApiCreateCronJobArgs': <classmethod object at 0x7fd0dcac9408>, '__doc__': u'Arguments for the CreateJob function.', 'protobuf': <class 'grr_response_proto.flows_pb2.CreateCronJobArgs'>}
{'__module__': 'grr_response_server.output_plugin', 'rdf_deps': [<class 'grr_response_server.rdfvalues.output_plugin.OutputPluginDescriptor'>], '__doc__': u'Describes processing status of a single batch by a hunt output plugin.', 'protobuf': <class 'grr_response_proto.output_plugin_pb2.OutputPluginBatchProcessingStatus'>}
{'CreatePluginAndDefaultState': <classmethod object at 0x7fd0dcade328>, '__module__': 'grr_response_server.output_plugin', 'description': u'', 'InitializeState': <function InitializeState at 0x7fd0dcae02a8>, 'args_type': None, 'UpdateState': <function UpdateState at 0x7fd0dcae0410>, '__init__': <function __init__ at 0x7fd0dcae0230>, 'Flush': <function Flush at 0x7fd0dcae0398>, 'ProcessResponses': <function ProcessResponses at 0x7fd0dcae0320>, '__doc__': u'The base class for output plugins.\n\n  Plugins process responses incrementally in small batches.\n\n  Every batch is processed via ProcessResponses() calls, which may be issued\n  in parallel for better performance. Then a single Flush() call is made.\n  Next batch of results may potentially be processed on a different worker,\n  therefore plugin\'s permanent state is stored in "state" attribute.\n  ', '_OutputPlugin__abstract': True, 'name': u''}
{'__module__': 'grr_response_server.output_plugin', 'description': u"Original plugin class couldn't be found.", 'args_type': <class 'grr_response_core.lib.rdfvalue.RDFBytes'>, 'name': u'unknown', '__doc__': u"Stub plugin used when original plugin class can't be found.", 'ProcessResponses': <function ProcessResponses at 0x7fd0dcae05f0>}
{'__module__': 'grr_response_server.rdfvalues.flow_objects', '__doc__': u'Descriptor of a pending flow termination.', 'protobuf': <class 'grr_response_proto.jobs_pb2.PendingFlowTermination'>}
{'__module__': 'grr_response_server.rdfvalues.flow_objects', 'protobuf': <class 'grr_response_proto.flows_pb2.FlowRequest'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.Dict'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetime'>]}
{'__module__': 'grr_response_server.rdfvalues.flow_objects', 'AsLegacyGrrMessage': <function AsLegacyGrrMessage at 0x7fd0dcae7de8>, 'protobuf': <class 'grr_response_proto.flows_pb2.FlowResponse'>, 'rdf_deps': []}
{'__module__': 'grr_response_server.rdfvalues.flow_objects', 'AsLegacyGrrMessage': <function AsLegacyGrrMessage at 0x7fd0dca6fe60>, 'protobuf': <class 'grr_response_proto.flows_pb2.FlowIterator'>, 'rdf_deps': []}
{'__module__': 'grr_response_server.rdfvalues.flow_objects', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client_stats.CpuSeconds'>], 'AsLegacyGrrMessage': <function AsLegacyGrrMessage at 0x7fd0dca72aa0>, '__doc__': u'The flow status object.', 'protobuf': <class 'grr_response_proto.flows_pb2.FlowStatus'>}
{'__module__': 'grr_response_server.rdfvalues.flow_objects', 'AsLegacyGrrMessage': <function AsLegacyGrrMessage at 0x7fd0dca7f488>, 'protobuf': <class 'grr_response_proto.flows_pb2.FlowResult'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>]}
{'__module__': 'grr_response_server.rdfvalues.flow_objects', 'protobuf': <class 'grr_response_proto.flows_pb2.FlowLogEntry'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>]}
{'ToOutputPluginBatchProcessingStatus': <function ToOutputPluginBatchProcessingStatus at 0x7fd0dca84ed8>, '__module__': 'grr_response_server.rdfvalues.flow_objects', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>], '__doc__': u'Log entry of a flow output plugin.', 'protobuf': <class 'grr_response_proto.flows_pb2.FlowOutputPluginLogEntry'>}
{'__module__': 'grr_response_server.rdfvalues.flow_objects', 'rdf_deps': [u'OutputPluginDescriptor', <class 'grr_response_server.rdfvalues.flow_runner.OutputPluginState'>, <class 'grr_response_server.rdfvalues.flow_objects.PendingFlowTermination'>, <class 'grr_response_core.lib.rdfvalues.client.ClientCrash'>, <class 'grr_response_core.lib.rdfvalues.client_stats.CpuSeconds'>, <class 'grr_response_server.rdfvalues.objects.FlowReference'>, <class 'grr_response_core.lib.rdfvalues.protodict.AttributedDict'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetime'>], '__doc__': u'Flow DB object.', '__init__': <function __init__ at 0x7fd0dca91140>, 'protobuf': <class 'grr_response_proto.flows_pb2.Flow'>}
{'__module__': 'grr_response_server.rdfvalues.hunt_objects', 'rdf_deps': [], '__doc__': u'Hunt arguments for standard (non-variable) hunts.', 'protobuf': <class 'grr_response_proto.hunts_pb2.HuntArgumentsStandard'>}
{'__module__': 'grr_response_server.rdfvalues.hunt_objects', 'rdf_deps': [], '__doc__': u'Flow group for variable hunt arguments.', 'protobuf': <class 'grr_response_proto.hunts_pb2.VariableHuntFlowGroup'>}
{'__module__': 'grr_response_server.rdfvalues.hunt_objects', 'rdf_deps': [<class 'grr_response_server.rdfvalues.hunt_objects.VariableHuntFlowGroup'>], '__doc__': u'Hunt arguments for variable hunts.', 'protobuf': <class 'grr_response_proto.hunts_pb2.HuntArgumentsVariable'>}
{'__module__': 'grr_response_server.rdfvalues.hunt_objects', 'rdf_deps': [<class 'grr_response_server.rdfvalues.hunt_objects.HuntArgumentsStandard'>, <class 'grr_response_server.rdfvalues.hunt_objects.HuntArgumentsVariable'>], 'Standard': <classmethod object at 0x7fd0dca28248>, 'Variable': <classmethod object at 0x7fd0dca28280>, '__doc__': u'Hunt arguments.', 'protobuf': <class 'grr_response_proto.hunts_pb2.HuntArguments'>}
{'__module__': 'grr_response_server.rdfvalues.hunt_objects', 'rdf_deps': [<class 'grr_response_server.rdfvalues.hunt_objects.HuntArguments'>, <class 'grr_response_server.foreman_rules.ForemanClientRuleSet'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetime'>, <class 'grr_response_server.rdfvalues.hunts.FlowLikeObjectReference'>, <class 'grr_response_server.rdfvalues.output_plugin.OutputPluginDescriptor'>], '__doc__': u'Hunt object.', '__init__': <function __init__ at 0x7fd0dca35398>, 'protobuf': <class 'grr_response_proto.hunts_pb2.Hunt'>}
{'CollectionReadIndex': <function CollectionReadIndex at 0x7fd0dc143a28>, 'EMPTY_DATA_PLACEHOLDER': u'X', 'FLOW_REQUEST_TEMPLATE': u'flow:request:%08X', '_CleanSubjectPrefix': <function _CleanSubjectPrefix at 0x7fd0dc141c80>, 'enable_flusher_thread': True, 'IndexRemoveKeywordsForName': <function IndexRemoveKeywordsForName at 0x7fd0dc1437d0>, 'DeleteSubjects': <function DeleteSubjects at 0x7fd0dc141578>, 'Initialize': <function Initialize at 0x7fd0dc141488>, 'ScanAttribute': <function ScanAttribute at 0x7fd0dc141de8>, 'Resolve': <function Resolve at 0x7fd0dc1418c0>, '_KeywordToURN': <function _KeywordToURN at 0x7fd0dc1436e0>, 'NOTIFY_PREDICATE_TEMPLATE': u'notify:%s', 'ReadResponses': <function ReadResponses at 0x7fd0dc1432a8>, 'FileHashIndexQueryMultiple': <function FileHashIndexQueryMultiple at 0x7fd0dc143cf8>, 'SetupTestDB': <classmethod object at 0x7fd0dc131b78>, 'ReadRequestsAndResponses': <function ReadRequestsAndResponses at 0x7fd0dc143140>, 'CollectionScanItems': <function CollectionScanItems at 0x7fd0dc1439b0>, 'NEWEST_TIMESTAMP': u'NEWEST_TIMESTAMP', 'FLOW_RESPONSE_PREFIX': u'flow:response:', 'GetFlowResponseSubject': <function GetFlowResponseSubject at 0x7fd0dc1430c8>, '__module__': 'grr_response_server.data_store', 'AFF4MultiFetchChildren': <function AFF4MultiFetchChildren at 0x7fd0dc143de8>, 'ReadCompletedRequests': <function ReadCompletedRequests at 0x7fd0dc1431b8>, 'ALL_TIMESTAMPS': u'ALL_TIMESTAMPS', 'GetNotifications': <function GetNotifications at 0x7fd0dc143050>, 'AFF4_INDEX_DIR_TEMPLATE': u'index:dir/%s', 'ScanAttributes': <function ScanAttributes at 0x7fd0dc141d70>, 'MultiResolvePrefix': <function MultiResolvePrefix at 0x7fd0dc141938>, 'ReadResponsesForRequestId': <function ReadResponsesForRequestId at 0x7fd0dc143230>, 'DeleteRequests': <function DeleteRequests at 0x7fd0dc143488>, '_RegisterSize': <function _RegisterSize at 0x7fd0dc141410>, 'FetchResponsesForWellKnownFlow': <function FetchResponsesForWellKnownFlow at 0x7fd0dc143668>, 'LABEL_ATTRIBUTE_TEMPLATE': u'index:label_%s', 'DeleteWellKnownFlowResponses': <function DeleteWellKnownFlowResponses at 0x7fd0dc1435f0>, 'FILE_HASH_PREFIX': u'index:target:', 'StoreRequestsAndResponses': <function StoreRequestsAndResponses at 0x7fd0dc143320>, 'FILE_HASH_TEMPLATE': u'index:target:%s', 'NOTIFY_PREDICATE_PREFIX': u'notify:', 'FileHashIndexQuery': <function FileHashIndexQuery at 0x7fd0dc143c80>, 'LockRetryWrapper': <function LockRetryWrapper at 0x7fd0dc141668>, 'CreateNotifications': <function CreateNotifications at 0x7fd0dc141ed8>, 'ResolvePrefix': <function ResolvePrefix at 0x7fd0dc1419b0>, 'TIMESTAMPS': [u'ALL_TIMESTAMPS', u'NEWEST_TIMESTAMP'], 'FLOW_REQUEST_PREFIX': u'flow:request:', 'monitor_thread': None, 'QUEUE_TASK_PREDICATE_TEMPLATE': u'task:%s', 'QueueTaskIdToColumn': <classmethod object at 0x7fd0dc131be8>, 'COLLECTION_INDEX_ATTRIBUTE_PREFIX': u'index:sc_', '_INDEX_COLUMN_FORMAT': u'kw_index:%s', 'LEASE_ATTRIBUTE': u'aff4:lease', 'CollectionReadItems': <function CollectionReadItems at 0x7fd0dc143b18>, 'COLLECTION_MAX_SUFFIX': 16777215, 'AFF4_INDEX_DIR_PREFIX': u'index:dir/', 'flusher_thread': None, 'FLOW_STATUS_TEMPLATE': u'flow:status:%08X', '__doc__': u'Abstract database access.', 'CollectionMakeURN': <classmethod object at 0x7fd0dc131bb0>, 'InitializeMonitorThread': <function InitializeMonitorThread at 0x7fd0dc141230>, '__del__': <function __del__ at 0x7fd0dc141c08>, 'QueueQueryTasks': <function QueueQueryTasks at 0x7fd0dc143b90>, 'AFF4FetchChildren': <function AFF4FetchChildren at 0x7fd0dc143d70>, 'LabelFetchAll': <function LabelFetchAll at 0x7fd0dc143c08>, 'Set': <function Set at 0x7fd0dc1415f0>, 'DeleteNotifications': <function DeleteNotifications at 0x7fd0dc141f50>, 'DestroyFlowStates': <function DestroyFlowStates at 0x7fd0dc143500>, 'QUEUE_TASK_PREDICATE_PREFIX': u'task:', 'mutation_pool_cls': <class 'grr_response_server.data_store.MutationPool'>, 'DeleteSubject': <function DeleteSubject at 0x7fd0dc141500>, 'Flush': <function Flush at 0x7fd0dc141b18>, 'ResolveMulti': <function ResolveMulti at 0x7fd0dc141a28>, 'DBSubjectLock': <function DBSubjectLock at 0x7fd0dc1416e0>, 'Size': <function Size at 0x7fd0dc141b90>, 'LABEL_ATTRIBUTE_PREFIX': u'index:label_', '_INDEX_PREFIX_LEN': 9, 'IndexAddKeywordsForName': <function IndexAddKeywordsForName at 0x7fd0dc143758>, 'MultiSet': <function MultiSet at 0x7fd0dc141758>, '_INDEX_PREFIX': u'kw_index:', '__init__': <function __init__ at 0x7fd0dc1411b8>, 'ResolveRow': <function ResolveRow at 0x7fd0dc141aa0>, 'MultiDeleteAttributes': <function MultiDeleteAttributes at 0x7fd0dc1417d0>, 'MultiDestroyFlowStates': <function MultiDestroyFlowStates at 0x7fd0dc143578>, 'GetMutationPool': <function GetMutationPool at 0x7fd0dc141e60>, 'CollectionReadStoredTypes': <function CollectionReadStoredTypes at 0x7fd0dc143aa0>, 'DeleteAttributes': <function DeleteAttributes at 0x7fd0dc141848>, 'FLOW_STATUS_PREFIX': u'flow:status:', 'CheckRequestsForCompletion': <function CheckRequestsForCompletion at 0x7fd0dc143398>, 'COLLECTION_VALUE_TYPE_PREFIX': u'aff4:value_type_', 'DeleteRequest': <function DeleteRequest at 0x7fd0dc143410>, 'ClearTestDB': <function ClearTestDB at 0x7fd0dc141320>, 'DestroyTestDB': <function DestroyTestDB at 0x7fd0dc141398>, '_CleanAfterURN': <function _CleanAfterURN at 0x7fd0dc141cf8>, 'QUEUE_LOCK_ATTRIBUTE': u'aff4:lease', 'FLOW_RESPONSE_TEMPLATE': u'flow:response:%08X:%08X', 'IndexReadPostingLists': <function IndexReadPostingLists at 0x7fd0dc143848>, 'COLLECTION_ATTRIBUTE': u'aff4:sequential_value'}
{'__module__': 'grr_response_server.data_store', 'Run': <function Run at 0x7fd0dc145500>, '__doc__': u'Initialize the data store.\n\n  Depends on the stats module being initialized.\n  ', '_ListStorageOptions': <function _ListStorageOptions at 0x7fd0dc145488>}
{'__module__': 'grr_response_server.rdfvalues.aff4', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>], 'Validate': <function Validate at 0x7fd0dc1457d0>, '__doc__': u'Labels are used to tag AFF4Objects.', '__init__': <function __init__ at 0x7fd0dc145758>, 'protobuf': <class 'grr_response_proto.jobs_pb2.AFF4ObjectLabel'>}
{'__module__': 'grr_response_server.rdfvalues.aff4', '__nonzero__': <function __nonzero__ at 0x7fd0dc0cb398>, 'rdf_deps': [<class 'grr_response_server.rdfvalues.aff4.AFF4ObjectLabel'>], '__getitem__': <function __getitem__ at 0x7fd0dc0cb230>, 'HasLabelWithNameAndOwner': <function HasLabelWithNameAndOwner at 0x7fd0dc0cb668>, 'RegexForStringifiedValueMatch': <staticmethod object at 0x7fd0dc0cc050>, '__str__': <function __str__ at 0x7fd0dc0cb1b8>, 'AddLabel': <function AddLabel at 0x7fd0dc0cb578>, '__iter__': <function __iter__ at 0x7fd0dc0cb320>, 'HasLabelWithName': <function HasLabelWithName at 0x7fd0dc0cb488>, 'names': <property object at 0x7fd0dc0ca158>, 'RemoveLabel': <function RemoveLabel at 0x7fd0dc0cb5f0>, 'GetLabelNames': <function GetLabelNames at 0x7fd0dc0cb500>, '__doc__': u'List of AFF4ObjectLabels.', '__len__': <function __len__ at 0x7fd0dc0cb2a8>, 'protobuf': <class 'grr_response_proto.jobs_pb2.AFF4ObjectLabelsList'>}
{'__module__': 'grr_response_server.aff4', 'Validate': <function Validate at 0x7fd0dc0d26e0>, '__doc__': u'An AFF4 attribute name.'}
{'ForceNewVersion': <function ForceNewVersion at 0x7fd0dc0d6b18>, '__module__': 'grr_response_server.aff4', '_AddAttributeToCache': <function _AddAttributeToCache at 0x7fd0dc0d60c8>, 'SetLabels': <function SetLabels at 0x7fd0dc0d80c8>, '_dirty': False, '__gt__': <function __gt__ at 0x7fd0dc0d6c08>, 'OnDelete': <function OnDelete at 0x7fd0dc0d6398>, 'Upgrade': <function Upgrade at 0x7fd0dc0d6aa0>, 'DecodeValueFromAttribute': <function DecodeValueFromAttribute at 0x7fd0dc0d6050>, '__exit__': <function __exit__ at 0x7fd0dc0d6de8>, '__lt__': <function __lt__ at 0x7fd0dc0d6c80>, '__init__': <function __init__ at 0x7fd0dc0d2ed8>, 'Schema': <property object at 0x7fd0dc0cacb0>, 'SetLabel': <function SetLabel at 0x7fd0dc0d8140>, '_SyncAttributes': <function _SyncAttributes at 0x7fd0dc0d6578>, 'Get': <function Get at 0x7fd0dc0d6938>, '__enter__': <function __enter__ at 0x7fd0dc0d6d70>, 'Update': <function Update at 0x7fd0dc0d6a28>, 'AddAttribute': <function AddAttribute at 0x7fd0dc0d6758>, 'behaviours': <grr_response_server.aff4.ClassProperty object at 0x7fd0dcff1390>, 'IsAttributeSet': <function IsAttributeSet at 0x7fd0dc0d68c0>, '_WriteAttributes': <function _WriteAttributes at 0x7fd0dc0d6488>, 'CheckLease': <function CheckLease at 0x7fd0dc0d6140>, 'RemoveLabels': <function RemoveLabels at 0x7fd0dc0d6f50>, 'Copy': <function Copy at 0x7fd0dc0d6668>, '__doc__': u'Base class for all objects.', 'GetLabels': <function GetLabels at 0x7fd0dc0d8230>, 'DeleteAttribute': <function DeleteAttribute at 0x7fd0dc0d6848>, '_CheckAttribute': <function _CheckAttribute at 0x7fd0dc0d65f0>, 'RemoveLabel': <function RemoveLabel at 0x7fd0dc0d8050>, 'GetValuesForAttribute': <function GetValuesForAttribute at 0x7fd0dc0d69b0>, 'Initialize': <function Initialize at 0x7fd0dc0d2f50>, 'Set': <function Set at 0x7fd0dc0d66e0>, '_RaiseLockError': <function _RaiseLockError at 0x7fd0dc0d61b8>, '__nonzero__': <function __nonzero__ at 0x7fd0dc0d6cf8>, 'ClearLabels': <function ClearLabels at 0x7fd0dc0d81b8>, 'transaction': None, 'locked': <property object at 0x7fd0dc0cac00>, 'SchemaCls': <class 'grr_response_server.aff4.SchemaCls'>, 'AddLabels': <function AddLabels at 0x7fd0dc0d6e60>, 'GetLabelsNames': <function GetLabelsNames at 0x7fd0dc0d82a8>, 'AddLabel': <function AddLabel at 0x7fd0dc0d6ed8>, '_behaviours': frozenset([]), '__repr__': <function __repr__ at 0x7fd0dc0d6b90>, 'Flush': <function Flush at 0x7fd0dc0d62a8>, 'Close': <function Close at 0x7fd0dc0d6320>, 'UpdateLease': <function UpdateLease at 0x7fd0dc0d6230>}
{'OpenChildren': <function OpenChildren at 0x7fd0dc0d8668>, '__module__': 'grr_response_server.aff4', 'SchemaCls': <class 'grr_response_server.aff4.SchemaCls'>, 'ListChildren': <function ListChildren at 0x7fd0dc0d85f0>, '_behaviours': frozenset([u'Container']), 'real_pathspec': <property object at 0x7fd0dc0caf70>, '__doc__': u'Volumes contain other objects.\n\n  The AFF4 concept of a volume abstracts away how objects are stored. We simply\n  define an AFF4 volume as a container of other AFF4 objects. The volume may\n  implement any storage mechanism it likes, including virtualizing the objects\n  contained within it.\n  '}
{'__module__': 'grr_response_server.aff4', '__doc__': u'The root of the VFS.'}
{'__module__': 'grr_response_server.aff4', '__doc__': u'This is a symlink to another AFF4 object.\n\n  This means that opening this object will return the linked to object. To\n  create a symlink, one must open the symlink for writing and set the\n  Schema.SYMLINK_TARGET attribute.\n\n  Opening the object for reading will return the linked to object.\n  ', 'SchemaCls': <class 'grr_response_server.aff4.SchemaCls'>, '__new__': <function __new__ at 0x7fd0dc0d8a28>}
{'write': <function Wrapped at 0x7fd0dc0df320>, '__module__': 'grr_response_server.aff4', 'GetContentAge': <function GetContentAge at 0x7fd0dc0df140>, 'SchemaCls': <class 'grr_response_server.aff4.SchemaCls'>, 'Read': <function Read at 0x7fd0dc0d8e60>, 'seek': <function Wrapped at 0x7fd0dc0df1b8>, 'flush': <function Wrapped at 0x7fd0dc0df398>, 'MultiStream': <classmethod object at 0x7fd0dc0cc4b0>, 'Tell': <function Tell at 0x7fd0dc0d8f50>, 'Write': <function Write at 0x7fd0dc0d8ed8>, 'read': <function read at 0x7fd0dc0df0c8>, 'tell': <function Wrapped at 0x7fd0dc0df230>, 'offset': 0, 'Initialize': <function Initialize at 0x7fd0dc0d8de8>, 'close': <function Wrapped at 0x7fd0dc0df2a8>, '_MultiStream': <classmethod object at 0x7fd0dc0cc478>, 'MULTI_STREAM_CHUNK_SIZE': 8388608, 'Seek': <function Seek at 0x7fd0dc0df050>, '__doc__': u'An abstract stream for reading data.', '__len__': <function __len__ at 0x7fd0dc0d8d70>, 'size': 0}
{'__module__': 'grr_response_server.aff4', 'GetContentAge': <function GetContentAge at 0x7fd0dc0df9b0>, 'Truncate': <function Truncate at 0x7fd0dc0df5f0>, 'Read': <function Read at 0x7fd0dc0df668>, 'OverwriteAndClose': <function OverwriteAndClose at 0x7fd0dc0df938>, 'Tell': <function Tell at 0x7fd0dc0df758>, 'Write': <function Write at 0x7fd0dc0df6e0>, 'Flush': <function Flush at 0x7fd0dc0df848>, 'Initialize': <function Initialize at 0x7fd0dc0df578>, 'Close': <function Close at 0x7fd0dc0df8c0>, 'Seek': <function Seek at 0x7fd0dc0df7d0>, '__doc__': u'A stream which keeps all data in memory.\n\n  This is an abstract class, subclasses must define the CONTENT attribute\n  in the Schema to be versioned or unversioned.\n  '}
{'__module__': 'grr_response_server.aff4', '__doc__': u'A versioned stream which keeps all data in memory.', 'SchemaCls': <class 'grr_response_server.aff4.SchemaCls'>}
{'__module__': 'grr_response_server.aff4', '__doc__': u'An unversioned stream which keeps all data in memory.', 'SchemaCls': <class 'grr_response_server.aff4.SchemaCls'>}
{'__module__': 'grr_response_server.aff4', 'NUM_RETRIES': 10, 'GetContentAge': <function GetContentAge at 0x7fd0dc0e27d0>, '_WritePartial': <function _WritePartial at 0x7fd0dc0e25f0>, '_GetChunkForReading': <function _GetChunkForReading at 0x7fd0dc0e2488>, 'Tell': <function Tell at 0x7fd0dc0e21b8>, 'Truncate': <function Truncate at 0x7fd0dc0e2230>, '_WriteChunk': <function _WriteChunk at 0x7fd0dc0e2398>, '_ReadChunks': <function _ReadChunks at 0x7fd0dc0e2320>, 'Initialize': <function Initialize at 0x7fd0dc0e2050>, '__getstate__': <function __getstate__ at 0x7fd0dc0e2848>, '__doc__': u'An AFF4 Image is stored in segments.\n\n  We are both an Image here and a volume (since we store the segments inside\n  us). This is an abstract class, subclasses choose the type to use for chunks.\n  ', 'SetChunksize': <function SetChunksize at 0x7fd0dc0e20c8>, 'CHUNK_ID_TEMPLATE': u'%010X', 'chunksize': 65536, '__setstate__': <function __setstate__ at 0x7fd0dc0e28c0>, 'STREAM_TYPE': None, 'LOOK_AHEAD': 10, '_GetChunkForWriting': <function _GetChunkForWriting at 0x7fd0dc0e2410>, 'Write': <function Write at 0x7fd0dc0e2668>, 'MULTI_STREAM_CHUNKS_READ_AHEAD': 1000, '_ReadChunk': <function _ReadChunk at 0x7fd0dc0e22a8>, 'SchemaCls': <class 'grr_response_server.aff4.SchemaCls'>, '_ReadPartial': <function _ReadPartial at 0x7fd0dc0e2500>, 'Read': <function Read at 0x7fd0dc0e2578>, 'Flush': <function Flush at 0x7fd0dc0e26e0>, '_GenerateChunkPaths': <classmethod object at 0x7fd0dcb13bb0>, 'Close': <function Close at 0x7fd0dc0e2758>, '_MultiStream': <classmethod object at 0x7fd0dc0cc440>, 'Seek': <function Seek at 0x7fd0dc0e2140>}
{'__module__': 'grr_response_server.aff4', 'STREAM_TYPE': <class 'grr_response_server.aff4.AFF4MemoryStream'>, '__doc__': u'An AFF4 Image containing a versioned stream.'}
{'__module__': 'grr_response_server.aff4', 'STREAM_TYPE': <class 'grr_response_server.aff4.AFF4UnversionedMemoryStream'>, '__doc__': u'An AFF4 Image containing an unversioned stream.'}
{'pre': [<class 'grr_response_server.data_store.DataStoreInit'>], '__module__': 'grr_response_server.aff4', 'Run': <function Run at 0x7fd0dc0e2d70>}
{'__module__': 'grr_response_core.lib.rdfvalues.nsrl', 'protobuf': <class 'grr_response_proto.jobs_pb2.NSRLInformation'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.HashDigest'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.events', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>, <class 'grr_response_core.lib.rdfvalue.RDFURN'>], '__doc__': u'An RDF wrapper for the `AuditEvent` protobuf.', '__init__': <function __init__ at 0x7fd0dc0a6410>, 'protobuf': <class 'grr_response_proto.jobs_pb2.AuditEvent'>}
{'ProcessMessages': <function ProcessMessages at 0x7fd0dc0c22a8>, '__module__': 'grr_response_server.events', 'ProcessMessage': <function ProcessMessage at 0x7fd0dc0c2320>, '__doc__': u'Base Class for all Event Listeners.\n\n  Event listeners can register for an event by specifying the event\n  name in the EVENTS constant.\n  ', 'EVENTS': []}
{'__module__': 'grr_response_core.lib.rdfvalues.chipsec_types', '__doc__': u'A request to Chipsec to dump the flash image (BIOS).', 'protobuf': <class 'grr_response_proto.chipsec_pb2.DumpFlashImageRequest'>}
{'__module__': 'grr_response_core.lib.rdfvalues.chipsec_types', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>], '__doc__': u'A response from Chipsec to dump the flash image (BIOS).', 'protobuf': <class 'grr_response_proto.chipsec_pb2.DumpFlashImageResponse'>}
{'__module__': 'grr_response_core.lib.rdfvalues.chipsec_types', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFBytes'>], '__doc__': u'Response from Chipsec for one ACPI table.', 'protobuf': <class 'grr_response_proto.chipsec_pb2.ACPITableData'>}
{'__module__': 'grr_response_core.lib.rdfvalues.chipsec_types', '__doc__': u'A request to Chipsec to dump an ACPI table.', 'protobuf': <class 'grr_response_proto.chipsec_pb2.DumpACPITableRequest'>}
{'__module__': 'grr_response_core.lib.rdfvalues.chipsec_types', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.chipsec_types.ACPITableData'>], '__doc__': u'A response from Chipsec to dump an ACPI table.', 'protobuf': <class 'grr_response_proto.chipsec_pb2.DumpACPITableResponse'>}
{'__module__': 'grr_response_core.lib.rdfvalues.file_finder', 'protobuf': <class 'grr_response_proto.flows_pb2.FileFinderModificationTimeCondition'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.file_finder', 'protobuf': <class 'grr_response_proto.flows_pb2.FileFinderAccessTimeCondition'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.file_finder', 'protobuf': <class 'grr_response_proto.flows_pb2.FileFinderInodeChangeTimeCondition'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.file_finder', 'protobuf': <class 'grr_response_proto.flows_pb2.FileFinderSizeCondition'>}
{'__module__': 'grr_response_core.lib.rdfvalues.file_finder', 'protobuf': <class 'grr_response_proto.flows_pb2.FileFinderExtFlagsCondition'>, '__init__': <function __init__ at 0x7fd0dc07e230>}
{'__module__': 'grr_response_core.lib.rdfvalues.file_finder', 'protobuf': <class 'grr_response_proto.flows_pb2.FileFinderContentsRegexMatchCondition'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.standard.RegularExpression'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.file_finder', 'protobuf': <class 'grr_response_proto.flows_pb2.FileFinderContentsLiteralMatchCondition'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.standard.LiteralExpression'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.file_finder', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderAccessTimeCondition'>, <class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderContentsLiteralMatchCondition'>, <class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderContentsRegexMatchCondition'>, <class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderInodeChangeTimeCondition'>, <class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderModificationTimeCondition'>, <class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderSizeCondition'>, <class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderExtFlagsCondition'>], 'ContentsLiteralMatch': <classmethod object at 0x7fd0dc008b08>, 'AccessTime': <classmethod object at 0x7fd0dc0089f0>, 'ModificationTime': <classmethod object at 0x7fd0dc008a28>, 'InodeChangeTime': <classmethod object at 0x7fd0dc008a60>, 'ExtFlags': <classmethod object at 0x7fd0dc008ad0>, 'ContentsRegexMatch': <classmethod object at 0x7fd0dc008b40>, 'Size': <classmethod object at 0x7fd0dc008a98>, '__doc__': u'An RDF value representing file finder conditions.', 'protobuf': <class 'grr_response_proto.flows_pb2.FileFinderCondition'>}
{'__module__': 'grr_response_core.lib.rdfvalues.file_finder', '__doc__': u'FileFinder stat action options RDFStruct.', '__init__': <function __init__ at 0x7fd0dc018758>, 'protobuf': <class 'grr_response_proto.flows_pb2.FileFinderStatActionOptions'>}
{'__module__': 'grr_response_core.lib.rdfvalues.file_finder', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.ByteSize'>], '__doc__': u'FileFinder hash action options RDFStruct.', '__init__': <function __init__ at 0x7fd0dc018de8>, 'protobuf': <class 'grr_response_proto.flows_pb2.FileFinderHashActionOptions'>}
{'__module__': 'grr_response_core.lib.rdfvalues.file_finder', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.ByteSize'>], '__doc__': u'FileFinder download action options RDFStruct.', '__init__': <function __init__ at 0x7fd0dc01f7d0>, 'protobuf': <class 'grr_response_proto.flows_pb2.FileFinderDownloadActionOptions'>}
{'Stat': <classmethod object at 0x7fd0dc016fa0>, 'Hash': <classmethod object at 0x7fd0dc016fd8>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderDownloadActionOptions'>, <class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderHashActionOptions'>, <class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderStatActionOptions'>], '__module__': 'grr_response_core.lib.rdfvalues.file_finder', 'Download': <classmethod object at 0x7fd0dc02d050>, '__doc__': u'An RDF value describing a file-finder action.', 'protobuf': <class 'grr_response_proto.flows_pb2.FileFinderAction'>}
{'__module__': 'grr_response_core.lib.rdfvalues.file_finder', 'protobuf': <class 'grr_response_proto.flows_pb2.FileFinderArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderAction'>, <class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderCondition'>, <class 'grr_response_core.lib.rdfvalues.paths.GlobExpression'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.file_finder', 'protobuf': <class 'grr_response_proto.flows_pb2.FileFinderResult'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client.BufferReference'>, <class 'grr_response_core.lib.rdfvalues.crypto.Hash'>, <class 'grr_response_core.lib.rdfvalues.client_fs.StatEntry'>, <class 'grr_response_core.lib.rdfvalues.client_fs.BlobImageDescriptor'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.osquery', 'rdf_deps': [], '__doc__': u'An RDF wrapper class for the `OsqueryArgs` proto.', 'protobuf': <class 'grr_response_proto.osquery_pb2.OsqueryArgs'>}
{'__module__': 'grr_response_core.lib.rdfvalues.osquery', 'rdf_deps': [], '__doc__': u'An RDF wrapper class for the `OsqueryColumn` proto.', 'protobuf': <class 'grr_response_proto.osquery_pb2.OsqueryColumn'>}
{'__module__': 'grr_response_core.lib.rdfvalues.osquery', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.osquery.OsqueryColumn'>], '__doc__': u'An RDF wrapper class for the `OsqueryHeader` proto.', 'protobuf': <class 'grr_response_proto.osquery_pb2.OsqueryHeader'>}
{'__module__': 'grr_response_core.lib.rdfvalues.osquery', 'rdf_deps': [], '__doc__': u'An RDF wrapper class for the `OsqueryRow` proto.', 'protobuf': <class 'grr_response_proto.osquery_pb2.OsqueryRow'>}
{'Column': <function Column at 0x7fd0dbfcc578>, '__module__': 'grr_response_core.lib.rdfvalues.osquery', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.osquery.OsqueryHeader'>, <class 'grr_response_core.lib.rdfvalues.osquery.OsqueryRow'>], '__doc__': u'An RDF wrapper class for the `OsqueryTable` proto.', 'protobuf': <class 'grr_response_proto.osquery_pb2.OsqueryTable'>}
{'__module__': 'grr_response_core.lib.rdfvalues.osquery', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.osquery.OsqueryTable'>], '__doc__': u'An RDF wrapper class for the `OsqueryTable` proto.', 'protobuf': <class 'grr_response_proto.osquery_pb2.OsqueryResult'>}
{'__module__': 'grr_response_core.lib.rdfvalues.plist', '__doc__': u'An argument that is a valid filter string parsed by query_parser_cls.\n\n  The class member query_parser_cls should be overriden by derived classes.\n  ', 'ParseFromString': <function ParseFromString at 0x7fd0dbfd1848>, 'query_parser_cls': <class 'grr_response_core.lib.lexer.SearchParser'>}
{'__module__': 'grr_response_core.lib.rdfvalues.plist', 'query_parser_cls': <class 'grr_response_core.lib.plist.PlistFilterParser'>}
{'__module__': 'grr_response_core.lib.rdfvalues.plist', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.PlistBoolDictEntry'>}
{'__module__': 'grr_response_core.lib.rdfvalues.plist', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.PlistStringDictEntry'>}
{'__module__': 'grr_response_core.lib.rdfvalues.plist', 'protobuf': <class 'grr_response_proto.jobs_pb2.PlistRequest'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>, <class 'grr_response_core.lib.rdfvalues.plist.PlistQuery'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.plist', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.LaunchdStartCalendarIntervalEntry'>}
{'__module__': 'grr_response_core.lib.rdfvalues.plist', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.LaunchdKeepAlive'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.plist.PlistBoolDictEntry'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.plist', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.LaunchdPlist'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.plist.LaunchdKeepAlive'>, <class 'grr_response_core.lib.rdfvalues.plist.LaunchdStartCalendarIntervalEntry'>, <class 'grr_response_core.lib.rdfvalues.plist.PlistStringDictEntry'>, <class 'grr_response_core.lib.rdfvalue.RDFURN'>]}
{'GetRules': <function GetRules at 0x7fd0dbf93c80>, '__module__': 'grr_response_core.lib.rdfvalues.rdf_yara'}
{'__module__': 'grr_response_core.lib.rdfvalues.rdf_yara', 'protobuf': <class 'grr_response_proto.flows_pb2.YaraProcessScanRequest'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraSignature'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.rdf_yara', 'protobuf': <class 'grr_response_proto.flows_pb2.YaraProcessError'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client.Process'>]}
{'FromLibYaraStringMatch': <classmethod object at 0x7fd0dbfa7750>, '__module__': 'grr_response_core.lib.rdfvalues.rdf_yara', 'rdf_deps': [], '__doc__': u'A result of Yara string matching.', 'protobuf': <class 'grr_response_proto.flows_pb2.YaraStringMatch'>}
{'FromLibYaraMatch': <classmethod object at 0x7fd0dbfa79b8>, '__module__': 'grr_response_core.lib.rdfvalues.rdf_yara', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraStringMatch'>], '__doc__': u'A result of Yara matching.', 'protobuf': <class 'grr_response_proto.flows_pb2.YaraMatch'>}
{'__module__': 'grr_response_core.lib.rdfvalues.rdf_yara', 'protobuf': <class 'grr_response_proto.flows_pb2.YaraProcessScanMatch'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client.Process'>, <class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraMatch'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.rdf_yara', 'protobuf': <class 'grr_response_proto.flows_pb2.YaraProcessScanMiss'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client.Process'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.rdf_yara', 'protobuf': <class 'grr_response_proto.flows_pb2.YaraProcessScanResponse'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessScanMatch'>, <class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessScanMiss'>, <class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessError'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.rdf_yara', 'protobuf': <class 'grr_response_proto.flows_pb2.YaraProcessDumpArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.ByteSize'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.rdf_yara', 'protobuf': <class 'grr_response_proto.flows_pb2.YaraProcessDumpInformation'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client.Process'>, <class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>]}
{'__module__': 'grr_response_core.lib.rdfvalues.rdf_yara', 'protobuf': <class 'grr_response_proto.flows_pb2.YaraProcessDumpResponse'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessDumpInformation'>, <class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessError'>]}
{'in_rdfvalue': None, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Stub for a client action. To be used in server code.', 'out_rdfvalues': [None]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.artifacts.ClientArtifactCollectorArgs'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'The client side artifact collector implementation.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.artifacts.ClientArtifactCollectorResult'>]}
{'__module__': 'grr_response_server.server_stubs', '__doc__': u'Estimate the install date of this system.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.protodict.DataBlob'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetime'>]}
{'__module__': 'grr_response_server.server_stubs', '__doc__': u'Enumerate all MAC addresses of all NICs.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client_network.Interface'>]}
{'__module__': 'grr_response_server.server_stubs', '__doc__': u'Enumerate all unique filesystems local to the system.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client_fs.Filesystem'>]}
{'__module__': 'grr_response_server.server_stubs', '__doc__': u'Remove the service that starts us at startup.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.protodict.DataBlob'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.client_action.ExecuteBinaryRequest'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Updates the GRR agent to a new version.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client_action.ExecuteBinaryResponse'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.client_action.WMIRequest'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Runs a WMI query and returns the results to a server callback.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.protodict.Dict'>]}
{'in_rdfvalue': None, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Enumerate all running launchd jobs.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client.OSXServiceInformation'>]}
{'in_rdfvalue': None, '__module__': 'grr_response_server.server_stubs', '__doc__': u'List running daemons.', 'out_rdfvalues': [None]}
{'__module__': 'grr_response_server.server_stubs', '__doc__': u'Enumerates all the users on this system.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client.User'>, <class 'grr_response_core.lib.rdfvalues.client.KnowledgeBaseUser'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.client_action.EchoRequest'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Returns a message to the server.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client_action.EchoRequest'>]}
{'__module__': 'grr_response_server.server_stubs', '__doc__': u'Retrieves the host name of the client.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.protodict.DataBlob'>]}
{'__module__': 'grr_response_server.server_stubs', '__doc__': u'Retrieves platform information.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client.Uname'>]}
{'__module__': 'grr_response_server.server_stubs', '__doc__': u'A client action for terminating (ClientActionStub) the client.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.flows.GrrMessage'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.protodict.DataBlob'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'A client action for simulating the client becoming unresponsive.'}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.protodict.DataBlob'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'A client action that burns cpu cycles. Used for testing cpu limits.'}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.protodict.DataBlob'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'A client action that uses lots of memory for testing.'}
{'in_rdfvalue': None, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Retrieves the running configuration parameters.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.protodict.Dict'>]}
{'in_rdfvalue': None, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Retrieves version information for installed libraries.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.protodict.Dict'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.protodict.Dict'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Updates configuration parameters on the client.'}
{'__module__': 'grr_response_server.server_stubs', '__doc__': u'Obtains information about the GRR client installed.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client.ClientInformation'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.client_action.GetClientStatsRequest'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'This retrieves some stats about the GRR process.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client_stats.ClientStats'>]}
{'__module__': 'grr_response_server.server_stubs', '__doc__': u'Action used to send the reply to a well known flow on the server.'}
{'__module__': 'grr_response_server.server_stubs', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client.StartupInfo'>]}
{'__module__': 'grr_response_server.server_stubs', '__doc__': u'Accepts a signed certificate from the server and saves it to disk.'}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.plist.PlistRequest'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Parses the plist request specified and returns the results.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.protodict.RDFValueArray'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.client.BufferReference'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Reads a buffer from a file and returns it to a server callback.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client.BufferReference'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.client.BufferReference'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Reads a buffer from a file and returns it to the server efficiently.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client.BufferReference'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.client.BufferReference'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Hash a buffer from a file and returns it to the server efficiently.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client.BufferReference'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.client_action.FingerprintRequest'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Hash an entire file using multiple algorithms.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client_action.FingerprintResponse'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.client_action.CopyPathToFileRequest'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Copy contents of a pathspec to a file on disk.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client_action.CopyPathToFileRequest'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.client_action.ListDirRequest'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Lists all the files in a directory.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client_fs.StatEntry'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.client_action.ListDirRequest'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Sends a StatEntry for a single file.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client_fs.StatEntry'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.client_action.GetFileStatRequest'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'A client action that yields stat of a given file.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client_fs.StatEntry'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.client_action.ExecuteRequest'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Executes one of the predefined commands.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client_action.ExecuteResponse'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.client_action.ExecuteBinaryRequest'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Executes a command from a passed in binary.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client_action.ExecuteBinaryResponse'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.client_action.ExecutePythonRequest'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Executes python code with exec.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client_action.ExecutePythonResponse'>]}
{'in_rdfvalue': None, '__module__': 'grr_response_server.server_stubs', '__doc__': u'This action is just for debugging. It induces a segfault.', 'out_rdfvalues': [None]}
{'in_rdfvalue': None, '__module__': 'grr_response_server.server_stubs', '__doc__': u'This action lists all the processes running on a machine.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client.Process'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.client_action.SendFileRequest'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'This action encrypts and sends a file to a remote listener.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client_fs.StatEntry'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.client_action.StatFSRequest'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Call os.statvfs for a given list of paths. OS X and Linux only.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client_fs.Volume'>]}
{'__module__': 'grr_response_server.server_stubs', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalue.ByteSize'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Delete all the GRR temp files in a directory.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client.LogMessage'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>, '__module__': 'grr_response_server.server_stubs', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client_fs.DiskUsage'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.client_fs.FindSpec'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Recurses through a directory returning files which match conditions.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client_fs.FindSpec'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.client_fs.GrepSpec'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Search a file for a pattern.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client.BufferReference'>]}
{'in_rdfvalue': None, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Gather open network connection stats.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client_network.NetworkConnection'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.client_action.ListNetworkConnectionsArgs'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Gather open network connection stats.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client_network.NetworkConnection'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.cloud.CloudMetadataRequests'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Get metadata for cloud VMs.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.cloud.CloudMetadataResponses'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderArgs'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'The file finder implementation using the OS file api.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderResult'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.client_action.FingerprintRequest'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Apply a set of fingerprinting methods to a file.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.client_action.FingerprintResponse'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.chipsec_types.DumpFlashImageRequest'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'A client action to collect the BIOS via SPI using Chipsec.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.chipsec_types.DumpFlashImageResponse'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.chipsec_types.DumpACPITableRequest'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'A client action to collect the ACPI table(s).', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.chipsec_types.DumpACPITableResponse'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessScanRequest'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Scans the memory of a number of processes using Yara.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessScanResponse'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessDumpArgs'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'Dumps a process to disk and returns pathspecs for GRR to pick up.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.rdf_yara.YaraProcessDumpResponse'>]}
{'in_rdfvalue': <class 'grr_response_core.lib.rdfvalues.osquery.OsqueryArgs'>, '__module__': 'grr_response_server.server_stubs', '__doc__': u'A stub class for the osquery action plugin.', 'out_rdfvalues': [<class 'grr_response_core.lib.rdfvalues.osquery.OsqueryResult'>]}
{'__module__': 'grr_response_server.sequential_collection', 'RunOnce': <function RunOnce at 0x7fd0dbcce668>, '__doc__': u'Init hook to start the background index updater.'}
{'__module__': 'grr_response_server.aff4_objects.users', '_CalculateHash': <function _CalculateHash at 0x7fd0dbcd1668>, 'CheckPassword': <function CheckPassword at 0x7fd0dbcd17d0>, '_MakeTemplate': <function _MakeTemplate at 0x7fd0dbcd1578>, 'safe_str_cmp': <function safe_str_cmp at 0x7fd0dbcd15f0>, 'SetPassword': <function SetPassword at 0x7fd0dbcd16e0>, '__doc__': u'Encoded crypted password.', '_CheckLegacyPassword': <function _CheckLegacyPassword at 0x7fd0dbcd1758>}
{'__module__': 'grr_response_server.aff4_objects.users', 'protobuf': <class 'grr_response_proto.user_pb2.GUISettings'>}
{'__module__': 'grr_response_server.aff4_objects.users', '_SYSTEM_USERS_LOWERCASE': set([u'grrworker', u'grrsystem', u'grrstatsstore', u'grrconsole', u'grrcron', u'grrendtoendtest', u'grrbenchmarktest', u'grrfrontend', u'grr', u'grrartifactregistry']), 'IsValidUsername': <staticmethod object at 0x7fd0dbcc2e18>, 'SchemaCls': <class 'grr_response_server.aff4_objects.users.SchemaCls'>, 'DeletePendingNotification': <function DeletePendingNotification at 0x7fd0dbcdd140>, 'Describe': <function Describe at 0x7fd0dbcdd230>, 'ShowNotifications': <function ShowNotifications at 0x7fd0dbcdd1b8>, 'SYSTEM_USERS': set([u'GRRWorker', u'GRRConsole', u'GRRSystem', u'GRRStatsStore', u'GRRFrontEnd', u'GRR', u'GRREndToEndTest', u'GRRBenchmarkTest', u'GRRCron', u'GRRArtifactRegistry']), 'Notify': <function Notify at 0x7fd0dbcdd0c8>, 'CheckPassword': <function CheckPassword at 0x7fd0dbcdd320>, 'SetPassword': <function SetPassword at 0x7fd0dbcdd2a8>, '__doc__': u'An AFF4 object modeling a GRR User.'}
{'__module__': 'grr_response_server.flow', '__doc__': u'Some flows do not take argumentnts.', 'protobuf': <class 'grr_response_proto.jobs_pb2.EmptyMessage'>}
{'__module__': 'grr_response_server.flow', 'FlushMessages': <function FlushMessages at 0x7fd0db1fcaa0>, 'End': <function End at 0x7fd0db1fcc08>, 'Log': <function Log at 0x7fd0db1fcf50>, 'creator': <property object at 0x7fd0db1fd0a8>, 'GetLog': <function GetLog at 0x7fd0db1fe050>, '_CheckLeaseAndFlush': <function _CheckLeaseAndFlush at 0x7fd0db1fc938>, 'CallClient': <function CallClient at 0x7fd0db1fe0c8>, 'Start': <function Start at 0x7fd0db1fcc80>, 'StartAFF4Flow': <function StartAFF4Flow at 0x7fd0db1fcde8>, 'Save': <function Save at 0x7fd0db1fcd70>, 'CallStateInline': <function CallStateInline at 0x7fd0db1fe140>, 'CallState': <function CallState at 0x7fd0db1fe1b8>, 'Initialize': <function Initialize at 0x7fd0db1fc7d0>, '__doc__': u'The base class for Flows and Hunts.', 'CreateRunner': <function CreateRunner at 0x7fd0db1fc848>, 'GetRunner': <function GetRunner at 0x7fd0db1fc8c0>, 'Load': <function Load at 0x7fd0db1fccf8>, 'ShouldSendNotifications': <function ShouldSendNotifications at 0x7fd0db1fcb18>, 'args_type': <class 'grr_response_server.flow.EmptyFlowArgs'>, 'Terminate': <function Terminate at 0x7fd0db1fcb90>, 'session_id': <property object at 0x7fd0db1fd050>, 'CallFlow': <function CallFlow at 0x7fd0db1fe230>, 'Flush': <function Flush at 0x7fd0db1fc9b0>, 'Close': <function Close at 0x7fd0db1fca28>}
{'__module__': 'grr_response_server.flow', 'friendly_name': None, 'NotifyAboutEnd': <function NotifyAboutEnd at 0x7fd0db1fe578>, 'outstanding_requests': <property object at 0x7fd0db1fd5d0>, 'ResultCollection': <function ResultCollection at 0x7fd0db1fede8>, 'TypedResultCollectionForFID': <classmethod object at 0x7fd0dbcee478>, 'logs_collection_urn': <property object at 0x7fd0db1fd6d8>, 'output_urn': <property object at 0x7fd0db1fd628>, 'category': u'', 'client_urn': <property object at 0x7fd0db1fd470>, 'TypedResultCollection': <function TypedResultCollection at 0x7fd0db1fef50>, 'SendReply': <function SendReply at 0x7fd0db1fe758>, 'behaviours': <grr_response_server.flow.FlowBehaviour object at 0x7fd0db1f7650>, 'client_os': <property object at 0x7fd0db1fd520>, 'Initialize': <function Initialize at 0x7fd0db1fe410>, '__doc__': u'A container aff4 object to maintain a flow.\n\n  Flow objects are executed and scheduled by the workers, and extend\n  grr.flow.GRRFlow. This object contains the flows object within an AFF4\n  container.\n\n  Note: Usually this object can not be created by users using the regular\n  aff4.FACTORY.Create() method since it requires elevated permissions. This\n  object can instead be created using the flow.StartAFF4Flow() method.\n\n  After creation, access to the flow object can still be obtained through\n  the usual aff4.FACTORY.Open() method.\n\n  The GRRFlow object should be extended by flow implementations, adding state\n  handling methods. The mechanics of running the flow are separated from the\n  flow itself, using the runner object. Then FlowRunner() for the flow can be\n  obtained from the flow.GetRunner(). The runner contains all the methods\n  specific to running, scheduling and interrogating the flow:\n\n\n  with aff4.FACTORY.Open(flow_urn, mode="rw") as fd:\n    runner = fd.GetRunner()\n    runner.ProcessCompletedRequests(messages)\n  ', 'GetDefaultArgs': <classmethod object at 0x7fd0dba45fa0>, 'LogCollection': <function LogCollection at 0x7fd0db202140>, 'Name': <function Name at 0x7fd0db1feb18>, 'CreateRunner': <function CreateRunner at 0x7fd0db1fe488>, 'ResultCollectionForFID': <classmethod object at 0x7fd0dbcee408>, '_ValidateState': <function _ValidateState at 0x7fd0db1fe668>, 'client_id': <property object at 0x7fd0db1fd418>, 'Error': <function Error at 0x7fd0db1fe7d0>, 'WriteState': <function WriteState at 0x7fd0db1fe6e0>, 'MarkForTermination': <classmethod object at 0x7fd0dba45fd8>, 'client_knowledge_base': <property object at 0x7fd0db1fd578>, 'LogCollectionForFID': <classmethod object at 0x7fd0dbcee638>, 'SchemaCls': <class 'grr_response_server.flow.SchemaCls'>, 'Terminate': <function Terminate at 0x7fd0db1fe848>, 'TerminateAFF4Flow': <classmethod object at 0x7fd0dba45f30>, 'HeartBeat': <function HeartBeat at 0x7fd0db1fe5f0>, 'client_version': <property object at 0x7fd0db1fd4c8>, 'multi_type_output_urn': <property object at 0x7fd0db1fd680>}
{'category': None, 'ProcessMessages': <function ProcessMessages at 0x7fd0db202668>, '__module__': 'grr_response_server.flow', 'UpdateKillNotification': <function UpdateKillNotification at 0x7fd0db2027d0>, 'ProcessResponses': <function ProcessResponses at 0x7fd0db2025f0>, 'FetchAndRemoveRequestsAndResponses': <function FetchAndRemoveRequestsAndResponses at 0x7fd0db202578>, 'FlushMessages': <function FlushMessages at 0x7fd0db202500>, 'GetAllWellKnownFlows': <classmethod object at 0x7fd0db2626e0>, 'session_id': <property object at 0x7fd0db1fd890>, 'outstanding_requests': <property object at 0x7fd0db1fd8e8>, '_ValidateState': <function _ValidateState at 0x7fd0db202758>, '_SafeProcessMessage': <function _SafeProcessMessage at 0x7fd0db202398>, 'ProcessMessage': <function ProcessMessage at 0x7fd0db2026e0>, '__doc__': u"A flow with a well known session_id.\n\n  Since clients always need to communicate with a flow, it is\n  impossible for them to asynchronously begin communication with the\n  server because normally the flow's session ID is randomly\n  generated. Sometimes we want the client to communicate with the\n  server spontaneously - so it needs a well known session ID.\n\n  This base class defines such flows with a well known\n  session_id. Clients can communicate with these flows by themselves\n  without prior arrangement.\n\n  Note that necessarily well known flows do not have any state and\n  therefore do not need state handlers. In this regard a WellKnownFlow\n  is basically an RPC mechanism - if you need to respond with a\n  complex sequence of actions you will need to spawn a new flow from\n  here.\n  ", 'well_known_session_id': None}
{'__module__': 'grr_response_server.aff4_objects.standard', '_behaviours': frozenset([u'Container']), '__doc__': u'This represents a directory from the client.', 'SchemaCls': <class 'grr_response_server.aff4_objects.standard.SchemaCls'>, 'Update': <function Update at 0x7fd0db202b18>}
{'__module__': 'grr_response_server.aff4_objects.standard', '__getitem__': <function __getitem__ at 0x7fd0db202de8>, '__iter__': <function __iter__ at 0x7fd0db202d70>, 'HASH_SIZE': 32, '__doc__': u'A list of hashes.', '__len__': <function __len__ at 0x7fd0db202cf8>}
{'AddBlob': <function AddBlob at 0x7fd0db20b500>, '_GetChunkForWriting': <function _GetChunkForWriting at 0x7fd0db20b2a8>, '__module__': 'grr_response_server.aff4_objects.standard', '_HASH_SIZE': 32, 'chunksize': 524288, 'SchemaCls': <class 'grr_response_server.aff4_objects.standard.SchemaCls'>, '_READAHEAD': 10, 'ChunksExist': <function ChunksExist at 0x7fd0db20b5f0>, '_ReadPartial': <function _ReadPartial at 0x7fd0db20b320>, 'Truncate': <function Truncate at 0x7fd0db20b488>, '_ChunkNrsToHashes': <function _ChunkNrsToHashes at 0x7fd0db20b1b8>, '_GetChunkForReading': <function _GetChunkForReading at 0x7fd0db20b230>, '_WriteChunk': <function _WriteChunk at 0x7fd0db20b0c8>, '_ReadChunks': <function _ReadChunks at 0x7fd0db20b050>, 'Read': <function Read at 0x7fd0db20b398>, 'Flush': <function Flush at 0x7fd0db20b6e0>, 'Initialize': <function Initialize at 0x7fd0db20b410>, 'ChunksMetadata': <function ChunksMetadata at 0x7fd0db20b668>, '_ChunkNrToHash': <function _ChunkNrToHash at 0x7fd0db20b140>, 'ChunkExists': <function ChunkExists at 0x7fd0db20b578>, '__doc__': u'A class to store partial files.'}
{'__module__': 'grr_response_server.aff4_objects.standard', 'Remove': <function Remove at 0x7fd0db20baa0>, 'CLIENT_LABELS_URN': u'aff4:/index/labels/client_set', 'Add': <function Add at 0x7fd0db20ba28>, 'Flush': <function Flush at 0x7fd0db20b938>, 'Close': <function Close at 0x7fd0db20b9b0>, '__doc__': u'An aff4 object which manages a set of labels.\n\n  This object has no actual attributes, it simply manages the set.\n  ', '__init__': <function __init__ at 0x7fd0db20b8c0>, 'ListLabels': <function ListLabels at 0x7fd0db20bb18>}
{'__module__': 'grr_response_server.aff4_objects.aff4_grr', '__iter__': <function __iter__ at 0x7fd0db20bcf8>, '__doc__': u'A special string which stores strings as space separated.', '__len__': <function __len__ at 0x7fd0db20bd70>}
{'CrashCollectionURNForCID': <classmethod object at 0x7fd0dbcc2ec0>, '__module__': 'grr_response_server.aff4_objects.aff4_grr', 'GetSummary': <function GetSummary at 0x7fd0db2142a8>, 'SchemaCls': <class 'grr_response_server.aff4_objects.aff4_grr.SchemaCls'>, 'age': <property object at 0x7fd0db208890>, 'CrashCollectionForCID': <classmethod object at 0x7fd0dbcc2948>, 'Update': <function Update at 0x7fd0db2141b8>, 'AddLabels': <function AddLabels at 0x7fd0db214320>, 'ClientURNFromURN': <staticmethod object at 0x7fd0dbcc2e50>, 'CLIENT_ID_RE': <_sre.SRE_Pattern object at 0x7fd0db252540>, 'CrashCollection': <function CrashCollection at 0x7fd0db214050>, 'Initialize': <function Initialize at 0x7fd0db214140>, '__doc__': u'A Remote client.'}
{'__module__': 'grr_response_server.aff4_objects.aff4_grr', 'protobuf': <class 'grr_response_proto.flows_pb2.UpdateVFSFileArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFURN'>]}
{'Start': <function Start at 0x7fd0db214b90>, '__module__': 'grr_response_server.aff4_objects.aff4_grr', 'args_type': <class 'grr_response_server.aff4_objects.aff4_grr.UpdateVFSFileArgs'>, '__doc__': u'A flow to update VFS file.', 'Init': <function Init at 0x7fd0db214b18>}
{'__module__': 'grr_response_server.aff4_objects.aff4_grr', '__doc__': u'A file object that can be updated under lock.', 'SchemaCls': <class 'grr_response_server.aff4_objects.aff4_grr.SchemaCls'>, 'Update': <function Update at 0x7fd0db214d70>}
{'__module__': 'grr_response_server.aff4_objects.aff4_grr', '__doc__': u'A VFS file under a VFSDirectory node which does not have storage.', 'SchemaCls': <class 'grr_response_server.aff4_objects.aff4_grr.SchemaCls'>}
{'_SetLastForemanRunTime': <function _SetLastForemanRunTime at 0x7fd0db21c410>, '__module__': 'grr_response_server.aff4_objects.aff4_grr', 'SchemaCls': <class 'grr_response_server.aff4_objects.aff4_grr.SchemaCls'>, '_EvaluateRules': <function _EvaluateRules at 0x7fd0db21c230>, '_CheckIfHuntTaskWasAssigned': <function _CheckIfHuntTaskWasAssigned at 0x7fd0db21c1b8>, '_GetLastForemanRunTimeRelational': <function _GetLastForemanRunTimeRelational at 0x7fd0db21c320>, '_GetLastForemanRunTime': <function _GetLastForemanRunTime at 0x7fd0db21c398>, '_RunActions': <function _RunActions at 0x7fd0db21c2a8>, 'ExpireRules': <function ExpireRules at 0x7fd0db21c140>, '_SetLastForemanRunTimeRelational': <function _SetLastForemanRunTimeRelational at 0x7fd0db21c488>, '__doc__': u'The foreman starts flows for clients depending on rules.', 'AssignTasksToClient': <function AssignTasksToClient at 0x7fd0db21c500>}
{'pre': [<class 'grr_response_server.aff4.AFF4InitHook'>], '__module__': 'grr_response_server.aff4_objects.aff4_grr', 'Run': <function Run at 0x7fd0db21c6e0>, '__doc__': u'Ensure critical AFF4 objects exist for GRR.'}
{'__module__': 'grr_response_server.aff4_objects.aff4_grr', 'SchemaCls': <class 'grr_response_server.aff4_objects.aff4_grr.SchemaCls'>, 'Read': <function Read at 0x7fd0db21c938>, 'Tell': <function Tell at 0x7fd0db21ca28>, 'Write': <function Write at 0x7fd0db21cb18>, 'delegate': None, 'Initialize': <function Initialize at 0x7fd0db21c8c0>, 'Close': <function Close at 0x7fd0db21caa0>, 'Seek': <function Seek at 0x7fd0db21c9b0>, '__doc__': u'A Delegate object for another URN.'}
{'_GenerateChunkIds': <classmethod object at 0x7fd0dbcc2ef8>, '_GetChunkForReading': <function _GetChunkForReading at 0x7fd0db21cf50>, '__module__': 'grr_response_server.aff4_objects.aff4_grr', '_HASH_SIZE': 32, 'GetContentAge': <function GetContentAge at 0x7fd0db2212a8>, 'Truncate': <function Truncate at 0x7fd0db21ce60>, '_READAHEAD': 5, 'AppendContent': <function AppendContent at 0x7fd0db2211b8>, 'MULTI_STREAM_CHUNKS_READ_AHEAD': 1000, '_GetChunkForWriting': <function _GetChunkForWriting at 0x7fd0db21ced8>, '_WriteChunk': <function _WriteChunk at 0x7fd0db2210c8>, '_ReadChunks': <function _ReadChunks at 0x7fd0db221050>, 'AddBlob': <function AddBlob at 0x7fd0db221230>, 'Flush': <function Flush at 0x7fd0db221140>, 'Initialize': <function Initialize at 0x7fd0db21cde8>, 'Path': <function Path at 0x7fd0db221320>, '_MultiStream': <classmethod object at 0x7fd0db262590>, 'SchemaCls': <class 'grr_response_server.aff4_objects.aff4_grr.SchemaCls'>, '__doc__': u'An AFF4 stream which stores chunks by hashes.\n\n  The hash stream is kept within an AFF4 Attribute, instead of another stream\n  making it more efficient for smaller files.\n  '}
{'__module__': 'grr_response_server.aff4_objects.aff4_grr', '__doc__': u'This is only used in end to end tests.', 'SchemaCls': <class 'grr_response_server.aff4_objects.aff4_grr.SchemaCls'>}
{'__module__': 'grr_response_server.aff4_objects.filestore', 'SchemaCls': <class 'grr_response_server.aff4_objects.filestore.SchemaCls'>, 'AddURN': <function AddURN at 0x7fd0db221758>, 'GetChildrenByPriority': <function GetChildrenByPriority at 0x7fd0db221668>, 'PRIORITY': 99, 'AddFile': <function AddFile at 0x7fd0db221848>, 'EXTERNAL': False, 'CHUNK_SIZE': 2621440, 'PATH': <aff4:/files age=1970-01-01 00:00:00>, 'AddURNToIndex': <function AddURNToIndex at 0x7fd0db2216e0>, '__doc__': u'Filestore for files downloaded from clients.\n\n  Modules can register for file content by creating paths under "aff4:/files".\n  By default files created in this namespace can be read by users that have the\n  URN (hash).  See lib/aff4_objects/user_managers.py.\n\n  Filestores are operated on according to their PRIORITY value, lowest first.\n  ', 'CheckHashes': <function CheckHashes at 0x7fd0db2217d0>}
{'__module__': 'grr_response_server.aff4_objects.filestore', '__doc__': u'The AFF4 files that are stored in the file store area.\n\n  This class is deprecated, the stored files are now just the original\n  type we used to download them - VFSBlobImage mostly. No special\n  treatment needed anymore.\n  '}
{'__module__': 'grr_response_server.aff4_objects.filestore', 'FromSerializedString': <classmethod object at 0x7fd0dc08cb40>, 'FromDatastoreValue': <classmethod object at 0x7fd0dc08cc20>, '_ParseUrn': <function _ParseUrn at 0x7fd0db221cf8>, '__doc__': u'Urns returned from HashFileStore.ListHashes().', '__init__': <function __init__ at 0x7fd0db221b90>}
{'_HashFile': <function _HashFile at 0x7fd0db227320>, '__module__': 'grr_response_server.aff4_objects.filestore', 'GetClientsForHashes': <classmethod object at 0x7fd0db262d70>, 'AddURN': <function AddURN at 0x7fd0db221ed8>, 'GetReferencesSHA1': <classmethod object at 0x7fd0db262c90>, 'GetReferencesMD5': <classmethod object at 0x7fd0dc098478>, 'HASH_TYPES': {u'generic': [u'md5', u'sha1', u'sha256', u'SignedData'], u'pecoff': [u'md5', u'sha1']}, 'ListHashes': <staticmethod object at 0x7fd0db262d00>, 'AddFile': <function AddFile at 0x7fd0db227398>, 'PRIORITY': 2, 'GetReferencesSHA256': <classmethod object at 0x7fd0db262cc8>, '_AddToIndex': <function _AddToIndex at 0x7fd0db221f50>, 'GetClientsForHash': <classmethod object at 0x7fd0db262d38>, 'EXTERNAL': False, 'Query': <classmethod object at 0x7fd0dc098130>, 'PATH': <aff4:/files/hash age=1970-01-01 00:00:00>, '_GetHashers': <function _GetHashers at 0x7fd0db2272a8>, '__doc__': u'FileStore that stores files referenced by hash.', 'CheckHashes': <function CheckHashes at 0x7fd0db227230>}
{'__module__': 'grr_response_server.aff4_objects.filestore', '__doc__': u'Represents a file from the NSRL database.', 'SchemaCls': <class 'grr_response_server.aff4_objects.filestore.SchemaCls'>}
{'__module__': 'grr_response_server.aff4_objects.filestore', 'AddHash': <function AddHash at 0x7fd0db227aa0>, 'AddURN': <function AddURN at 0x7fd0db227938>, 'GetChildrenByPriority': <function GetChildrenByPriority at 0x7fd0db227848>, 'ListHashes': <staticmethod object at 0x7fd0db262da8>, 'PRIORITY': 1, 'AddFile': <function AddFile at 0x7fd0db227b18>, 'EXTERNAL': False, 'NSRLInfoForSHA1s': <function NSRLInfoForSHA1s at 0x7fd0db2279b0>, 'PATH': <aff4:/files/nsrl age=1970-01-01 00:00:00>, 'FILE_TYPES': {u'': <EnumNamedValue('NORMAL_FILE')>, u'S': <EnumNamedValue('SPECIAL_FILE')>, u'M': <EnumNamedValue('MALICIOUS_FILE')>}, '__doc__': u'FileStore with NSRL hashes.', 'CheckHashes': <function CheckHashes at 0x7fd0db227a28>}
{'pre': [<class 'grr_response_server.aff4_objects.aff4_grr.GRRAFF4Init'>], '__module__': 'grr_response_server.aff4_objects.filestore', 'Run': <function Run at 0x7fd0db227cf8>, '__doc__': u'Create filestore aff4 paths.'}
{'__module__': 'grr_response_core.lib.rdfvalues.cronjobs', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.CronTabEntry'>}
{'__module__': 'grr_response_core.lib.rdfvalues.cronjobs', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.CronTabFile'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.cronjobs.CronTabEntry'>, <class 'grr_response_core.lib.rdfvalue.RDFURN'>]}
{'__module__': 'grr_response_core.lib.parser', 'output_types': [], 'GetDescription': <classmethod object at 0x7fd0db1ca910>, 'GetClassesByArtifact': <classmethod object at 0x7fd0db1ca8d8>, 'supported_artifacts': [], 'knowledgebase_dependencies': [], '__doc__': u'A class for looking up parsers.\n\n  Parsers may be in other libraries or third party code, this class keeps\n  references to each of them so they can be called by name by the artifacts.\n  '}
{'CheckReturn': <function CheckReturn at 0x7fd0db1d59b0>, '__module__': 'grr_response_core.lib.parser', '_CommandParser__abstract': True, 'ParseResponse': <function ParseResponse at 0x7fd0db1d5938>, 'Parse': <function Parse at 0x7fd0db1d58c0>, '__doc__': u'Abstract parser for processing command output.\n\n  Must implement the Parse function.\n\n  '}
{'Parse': <function Parse at 0x7fd0db1d5b90>, 'ParseFile': <function ParseFile at 0x7fd0db1d5c08>, '__module__': 'grr_response_core.lib.parser', '__doc__': u'Abstract parser for processing files output.\n\n  Must implement the Parse function.\n  ', '_FileParser__abstract': True}
{'ParseFiles': <function ParseFiles at 0x7fd0db1d5e60>, '__module__': 'grr_response_core.lib.parser', 'ParseMultiple': <function ParseMultiple at 0x7fd0db1d5de8>, '__doc__': u'Abstract parser for processing files output.'}
{'Parse': <function Parse at 0x7fd0db1df0c8>, 'ParseResponse': <function ParseResponse at 0x7fd0db1df140>, '__module__': 'grr_response_core.lib.parser', '__doc__': u'Abstract parser for processing WMI query output.'}
{'Parse': <function Parse at 0x7fd0db1df320>, 'ParseResponse': <function ParseResponse at 0x7fd0db1df398>, '__module__': 'grr_response_core.lib.parser', '__doc__': u'Abstract parser for processing Registry values.'}
{'Parse': <function Parse at 0x7fd0db1df578>, 'ParseResponse': <function ParseResponse at 0x7fd0db1df5f0>, '__module__': 'grr_response_core.lib.parser', '__doc__': u'Abstract parser for processing Registry values.'}
{'ParseResponses': <function ParseResponses at 0x7fd0db1df848>, '__module__': 'grr_response_core.lib.parser', 'ParseMultiple': <function ParseMultiple at 0x7fd0db1df7d0>, '__doc__': u'Abstract parser for processing registry values.'}
{'Parse': <function Parse at 0x7fd0db1dfa28>, 'ParseResponse': <function ParseResponse at 0x7fd0db1dfaa0>, '__module__': 'grr_response_core.lib.parser', '__doc__': u'Parser for the results of grep artifacts.'}
{'Parse': <function Parse at 0x7fd0db1dfc80>, 'ParseResponse': <function ParseResponse at 0x7fd0db1dfcf8>, '__module__': 'grr_response_core.lib.parser', '__doc__': u'Abstract parser for processing artifact files.'}
{'ParseResponses': <function ParseResponses at 0x7fd0db1dff50>, '__module__': 'grr_response_core.lib.parser', 'ParseMultiple': <function ParseMultiple at 0x7fd0db1dfed8>, '__doc__': u'Abstract multi-parser for processing artifact files.'}
{'__module__': 'grr_response_core.lib.rdfvalues.anomaly', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>], '__doc__': u'An RDFValue representation of an artifact.', 'protobuf': <class 'grr_response_proto.anomaly_pb2.Anomaly'>}
{'__module__': 'grr_response_core.lib.rdfvalues.config_file', '__doc__': u'An RDFValue represenation of a logging target.', 'protobuf': <class 'grr_response_proto.config_file_pb2.LogTarget'>}
{'__module__': 'grr_response_core.lib.rdfvalues.config_file', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.config_file.LogTarget'>], '__doc__': u'An RDFValue represenation of a logging configuration.', 'protobuf': <class 'grr_response_proto.config_file_pb2.LogConfig'>}
{'__module__': 'grr_response_core.lib.rdfvalues.config_file', '__doc__': u'An RDFValue representation of an NFS Client configuration.', 'protobuf': <class 'grr_response_proto.config_file_pb2.NfsClient'>}
{'__module__': 'grr_response_core.lib.rdfvalues.config_file', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.config_file.NfsClient'>], '__doc__': u'An RDFValue representation of an NFS Export entry.', 'protobuf': <class 'grr_response_proto.config_file_pb2.NfsExport'>}
{'__module__': 'grr_response_core.lib.rdfvalues.config_file', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.AttributedDict'>], '__doc__': u'An RDFValue representation of an sshd config match block.', 'protobuf': <class 'grr_response_proto.config_file_pb2.SshdMatchBlock'>}
{'__module__': 'grr_response_core.lib.rdfvalues.config_file', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.AttributedDict'>, <class 'grr_response_core.lib.rdfvalues.config_file.SshdMatchBlock'>], '__doc__': u'An RDFValue representation of a sshd config file.', 'protobuf': <class 'grr_response_proto.config_file_pb2.SshdConfig'>}
{'__module__': 'grr_response_core.lib.rdfvalues.config_file', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.AttributedDict'>], '__doc__': u'An RDFValue representation of a ntp config file.', 'protobuf': <class 'grr_response_proto.config_file_pb2.NtpConfig'>}
{'__module__': 'grr_response_core.lib.rdfvalues.config_file', '__doc__': u'An RDFValue representation of a single entry in a PAM configuration.', 'protobuf': <class 'grr_response_proto.config_file_pb2.PamConfigEntry'>}
{'__module__': 'grr_response_core.lib.rdfvalues.config_file', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.config_file.PamConfigEntry'>], '__doc__': u'An RDFValue representation of an entire PAM configuration.', 'protobuf': <class 'grr_response_proto.config_file_pb2.PamConfig'>}
{'__module__': 'grr_response_core.lib.rdfvalues.config_file', '__doc__': u'An RDFValue representation of a sudoers alias.', 'protobuf': <class 'grr_response_proto.config_file_pb2.SudoersAlias'>}
{'__module__': 'grr_response_core.lib.rdfvalues.config_file', '__doc__': u'An RDFValue representation of a sudoers default.', 'protobuf': <class 'grr_response_proto.config_file_pb2.SudoersDefault'>}
{'__module__': 'grr_response_core.lib.rdfvalues.config_file', '__doc__': u'An RDFValue representation of a sudoers file command list entry.', 'protobuf': <class 'grr_response_proto.config_file_pb2.SudoersEntry'>}
{'__module__': 'grr_response_core.lib.rdfvalues.config_file', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.config_file.SudoersAlias'>, <class 'grr_response_core.lib.rdfvalues.config_file.SudoersDefault'>, <class 'grr_response_core.lib.rdfvalues.config_file.SudoersEntry'>], '__doc__': u'An RDFValue representation of a sudoers config file.', 'protobuf': <class 'grr_response_proto.config_file_pb2.SudoersConfig'>}
{'__module__': 'grr_response_core.lib.parsers.config_file', 'output_types': [u'NfsExport'], 'Parse': <function Parse at 0x7fd0db18a0c8>, 'supported_artifacts': [u'NfsExportsFile'], '__doc__': u'Parser for NFS exports.', '__init__': <function __init__ at 0x7fd0db18a050>}
{'__module__': 'grr_response_core.lib.parsers.config_file', 'output_types': [u'SshdConfig'], 'Parse': <function Parse at 0x7fd0db18a668>, 'supported_artifacts': [u'SshdConfigFile'], '__doc__': u'A parser for sshd_config files.', '__init__': <function __init__ at 0x7fd0db18a5f0>}
{'__module__': 'grr_response_core.lib.parsers.config_file', 'output_types': [u'SshdConfig'], 'Parse': <function Parse at 0x7fd0db18a8c0>, 'supported_artifacts': [u'SshdConfigCmd'], '__doc__': u'A command parser for sshd -T output.', '__init__': <function __init__ at 0x7fd0db18a848>}
{'__module__': 'grr_response_core.lib.parsers.config_file', 'output_types': [u'Filesystem'], 'Parse': <function Parse at 0x7fd0db18ab18>, 'supported_artifacts': [u'LinuxProcMounts', u'LinuxFstab'], '__doc__': u'Parser for mounted filesystem data acquired from /proc/mounts.', '__init__': <function __init__ at 0x7fd0db18aaa0>}
{'mount_re': <_sre.SRE_Pattern object at 0x7fd0dc023d68>, '__module__': 'grr_response_core.lib.parsers.config_file', 'output_types': [u'Filesystem'], 'Parse': <function Parse at 0x7fd0db18ad70>, 'supported_artifacts': [u'LinuxMountCmd'], '__doc__': u'Parser for mounted filesystem data acquired from the mount command.', '__init__': <function __init__ at 0x7fd0db18acf8>}
{'__module__': 'grr_response_core.lib.parsers.config_file', 'ParseMultiple': <function ParseMultiple at 0x7fd0db1500c8>, 'output_types': [u'AttributedDict'], 'supported_artifacts': [u'LinuxRsyslogConfigs'], '__doc__': u'Artifact parser for syslog configurations.', '__init__': <function __init__ at 0x7fd0db150050>}
{'__module__': 'grr_response_core.lib.parsers.config_file', 'output_types': [u'AttributedDict'], '__doc__': u'Common code for APT and YUM source list parsing.', 'Parse': <function Parse at 0x7fd0db1502a8>, 'ParseURIFromKeyValues': <function ParseURIFromKeyValues at 0x7fd0db150398>, '_PackageSourceParser__abstract': True, 'FindPotentialURIs': <function FindPotentialURIs at 0x7fd0db150320>}
{'FindPotentialURIs': <function FindPotentialURIs at 0x7fd0db150578>, '__module__': 'grr_response_core.lib.parsers.config_file', '__doc__': u'Parser for APT source lists to extract URIs only.', 'supported_artifacts': [u'APTSources']}
{'FindPotentialURIs': <function FindPotentialURIs at 0x7fd0db150758>, '__module__': 'grr_response_core.lib.parsers.config_file', '__doc__': u'Parser for Yum source lists to extract URIs only.', 'supported_artifacts': [u'YumSources']}
{'Parse': <function Parse at 0x7fd0db150938>, 'output_types': [u'AttributedDict'], '__module__': 'grr_response_core.lib.parsers.config_file', '__doc__': u'Parser for /etc/cron.allow /etc/cron.deny /etc/at.allow & /etc/at.deny.', 'supported_artifacts': [u'CronAtAllowDenyFiles']}
{'Parse': <function Parse at 0x7fd0db150c08>, '__module__': 'grr_response_core.lib.parsers.config_file', 'ParseMultiple': <function ParseMultiple at 0x7fd0db150c80>, '__doc__': u'Artifact parser for ntpd.conf file.'}
{'__module__': 'grr_response_core.lib.parsers.config_file', 'output_types': [u'SudoersConfig'], 'Parse': <function Parse at 0x7fd0db158140>, 'supported_artifacts': [u'UnixSudoersConfiguration'], '__doc__': u'Artifact parser for privileged configuration files.', '__init__': <function __init__ at 0x7fd0db1580c8>}
{'Parse': <function Parse at 0x7fd0db0f6ed8>, 'output_types': [u'CronTabFile'], '__module__': 'grr_response_core.lib.parsers.cron_file_parser', '__doc__': u'Parser for crontab files.', 'supported_artifacts': [u'LinuxCronTabs', u'MacOSCronTabs']}
{'__module__': 'grr_response_core.lib.rdfvalues.webhistory', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.BrowserHistoryItem'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>]}
{'Parse': <function Parse at 0x7fd0db0fc8c0>, 'output_types': [u'BrowserHistoryItem'], '__module__': 'grr_response_core.lib.parsers.ie_history', '__doc__': u'Parse IE index.dat files into BrowserHistoryItem objects.', 'supported_artifacts': [u'InternetExplorerHistory']}
{'Parse': <function Parse at 0x7fd0db102578>, 'output_types': [u'SoftwarePackage'], '__module__': 'grr_response_core.lib.parsers.linux_cmd_parser', '__doc__': u"Parser for yum list output. Yields SoftwarePackage rdfvalues.\n\n  We read the output of yum rather than rpm because it has publishers, and we\n  don't use bdb because it's a world of hurt and appears to use different,\n  incompatible versions across OS revisions.\n  ", 'supported_artifacts': [u'RedhatYumPackagesList']}
{'_re_compile': <function _re_compile at 0x7fd0db102758>, '__module__': 'grr_response_core.lib.parsers.linux_cmd_parser', 'output_types': [u'PackageRepository'], 'Parse': <function Parse at 0x7fd0db1027d0>, 'supported_artifacts': [u'RedhatYumRepoList'], '__doc__': u'Parser for yum repolist output. Yields PackageRepository.\n\n  Parse all enabled repositories as output by yum repolist -q -v.\n  '}
{'Parse': <function Parse at 0x7fd0db1029b0>, 'output_types': [u'SoftwarePackage'], '__module__': 'grr_response_core.lib.parsers.linux_cmd_parser', '__doc__': u'Parser for rpm qa output. Yields SoftwarePackage rdfvalues.', 'supported_artifacts': [u'RedhatPackagesList']}
{'Parse': <function Parse at 0x7fd0db102b90>, 'output_types': [u'SoftwarePackage'], '__module__': 'grr_response_core.lib.parsers.linux_cmd_parser', '__doc__': u'Parser for dpkg output. Yields SoftwarePackage rdfvalues.', 'supported_artifacts': [u'DebianPackagesList']}
{'_re_compile': <function _re_compile at 0x7fd0db102d70>, '__module__': 'grr_response_core.lib.parsers.linux_cmd_parser', 'output_types': [u'HardwareInfo'], 'Parse': <function Parse at 0x7fd0db102de8>, 'supported_artifacts': [u'LinuxHardwareInfo'], '__doc__': u'Parser for dmidecode output. Yields HardwareInfo rdfvalues.'}
{'Parse': <function Parse at 0x7fd0db10a050>, 'output_types': [u'Process'], '__module__': 'grr_response_core.lib.parsers.linux_cmd_parser', '__doc__': u"Parser for '/bin/ps' output. Yields Process rdfvalues.", 'supported_artifacts': [u'ListProcessesPsCommand']}
{'output_types': [u'PCIDevice'], '__module__': 'grr_response_core.lib.parsers.linux_file_parser', 'ParseMultiple': <function ParseMultiple at 0x7fd0db113cf8>, '__doc__': u"Parser for PCI devices' info files located in /sys/bus/pci/devices/*/*.", 'supported_artifacts': [u'PCIDevicesInfoFiles']}
{'__module__': 'grr_response_core.lib.parsers.linux_file_parser', 'output_types': [u'User'], 'Parse': <function Parse at 0x7fd0db113f50>, 'supported_artifacts': [u'UnixPasswd'], 'ParseLine': <classmethod object at 0x7fd0db0fefd8>, '__doc__': u'Parser for passwd files. Yields User semantic values.'}
{'Parse': <function Parse at 0x7fd0db11b1b8>, 'output_types': [u'User'], '__module__': 'grr_response_core.lib.parsers.linux_file_parser', '__doc__': u'Parser for lines grepped from passwd files.', 'supported_artifacts': [u'LinuxPasswdHomedirs', u'NssCacheLinuxPasswdHomedirs']}
{'Parse': <function Parse at 0x7fd0db11b398>, 'output_types': [u'User'], '__module__': 'grr_response_core.lib.parsers.linux_file_parser', '__doc__': u'Simplified parser for linux wtmp files.\n\n  Yields User semantic values for USER_PROCESS events.\n  ', 'supported_artifacts': [u'LinuxWtmp']}
{'__module__': 'grr_response_core.lib.parsers.linux_file_parser', 'ParseLines': <classmethod object at 0x7fd0db11f050>, 'output_types': [u'User'], 'Parse': <function Parse at 0x7fd0db11b5f0>, 'supported_artifacts': [u'NetgroupConfiguration'], 'USERNAME_REGEX': u'^[a-z_][a-z0-9_-]{0,30}[$]?$', '__doc__': u'Parser that extracts users from a netgroup file.'}
{'Parse': <function Parse at 0x7fd0db11b7d0>, 'output_types': [u'User'], '__module__': 'grr_response_core.lib.parsers.linux_file_parser', '__doc__': u'Parser for lines grepped from /etc/netgroup files.'}
{'MemberDiff': <staticmethod object at 0x7fd0db11f088>, '__module__': 'grr_response_core.lib.parsers.linux_file_parser', 'ParseMultiple': <function ParseMultiple at 0x7fd0db11bcf8>, '_ParseFile': <function _ParseFile at 0x7fd0db11bb18>, 'base_store': None, '_LinuxBaseShadowParser__abstract': True, 'shadow_store': None, '_Anomaly': <function _Anomaly at 0x7fd0db11bc08>, 'GetHashType': <function GetHashType at 0x7fd0db11baa0>, 'hashes': [(u'SHA512', <_sre.SRE_Pattern object at 0x7fd0db124030>), (u'SHA256', <_sre.SRE_Pattern object at 0x7fd0db124168>), (u'DISABLED', <_sre.SRE_Pattern object at 0x7fd0db10e350>), (u'UNSET', <_sre.SRE_Pattern object at 0x7fd0db10e3f0>), (u'MD5', <_sre.SRE_Pattern object at 0x7fd0db245710>), (u'DES', <_sre.SRE_Pattern object at 0x7fd0db104440>), (u'BLOWFISH', <_sre.SRE_Pattern object at 0x7fd0db1242a0>), (u'NTHASH', <_sre.SRE_Pattern object at 0x7fd0db126030>), (u'UNUSED', <_sre.SRE_Pattern object at 0x7fd0db1260d8>)], 'GetPwStore': <function GetPwStore at 0x7fd0db11ba28>, '__doc__': u'Base parser to process user/groups with shadow files.', '__init__': <function __init__ at 0x7fd0db11b9b0>, 'ReconcileShadow': <function ReconcileShadow at 0x7fd0db11bb90>}
{'ParseGshadowEntry': <function ParseGshadowEntry at 0x7fd0db11bf50>, '__module__': 'grr_response_core.lib.parsers.linux_file_parser', 'MergeMembers': <function MergeMembers at 0x7fd0db1270c8>, 'output_types': [u'Group'], 'FindAnomalies': <function FindAnomalies at 0x7fd0db127140>, 'base_store': <EnumNamedValue('GROUP')>, 'ParseFileset': <function ParseFileset at 0x7fd0db1271b8>, 'shadow_store': <EnumNamedValue('GSHADOW')>, 'supported_artifacts': [u'LoginPolicyConfiguration'], '__doc__': u'Parser for group files. Yields Group semantic values.', '__init__': <function __init__ at 0x7fd0db11bed8>, 'ParseGroupEntry': <function ParseGroupEntry at 0x7fd0db127050>}
{'__module__': 'grr_response_core.lib.parsers.linux_file_parser', 'output_types': [u'User'], 'FindAnomalies': <function FindAnomalies at 0x7fd0db1275f0>, 'AddPassword': <function AddPassword at 0x7fd0db127668>, 'AddGroupMemberships': <function AddGroupMemberships at 0x7fd0db127578>, 'base_store': <EnumNamedValue('PASSWD')>, '_Members': <function _Members at 0x7fd0db127500>, 'ParseFileset': <function ParseFileset at 0x7fd0db127758>, 'shadow_store': <EnumNamedValue('SHADOW')>, 'supported_artifacts': [u'LoginPolicyConfiguration'], 'AddShadow': <function AddShadow at 0x7fd0db1276e0>, 'ParseShadowEntry': <function ParseShadowEntry at 0x7fd0db127410>, '__doc__': u'Parser for local accounts.', '__init__': <function __init__ at 0x7fd0db127398>, 'ParsePasswdEntry': <function ParsePasswdEntry at 0x7fd0db127488>}
{'__module__': 'grr_response_core.lib.parsers.linux_file_parser', '_ParseCshVariables': <function _ParseCshVariables at 0x7fd0db127aa0>, 'output_types': [u'AttributedDict'], '_CSH_FILES': (u'.login', u'.cshrc', u'.tcsh', u'csh.cshrc', u'csh.login', u'csh.logout'), '_ExpandPath': <function _ExpandPath at 0x7fd0db1279b0>, 'Parse': <function Parse at 0x7fd0db127b18>, '_CSH_SET_RE': <_sre.SRE_Pattern object at 0x7fd0dbfc6a30>, 'supported_artifacts': [u'GlobalShellConfigs', u'RootUserShellConfigs', u'UsersShellConfigs'], '_SHELLVAR_RE': <_sre.SRE_Pattern object at 0x7fd0dc14be90>, '_SH_CONTINUATION': (u'{', u'}', u'||', u'&&', u'export'), '_ParseShVariables': <function _ParseShVariables at 0x7fd0db127a28>, '_TARGETS': (u'CLASSPATH', u'LD_AOUT_LIBRARY_PATH', u'LD_AOUT_PRELOAD', u'LD_LIBRARY_PATH', u'LD_PRELOAD', u'MODULE_PATH', u'PATH', u'PERL5LIB', u'PERLLIB', u'PYTHONPATH', u'RUBYLIB'), '__doc__': u"Parser for dotfile entries.\n\n  Extracts path attributes from dotfiles to infer effective paths for users.\n  This parser doesn't attempt or expect to determine path state for all cases,\n  rather, it is a best effort attempt to detect common misconfigurations. It is\n  not intended to detect maliciously obfuscated path modifications.\n  ", '__init__': <function __init__ at 0x7fd0db127938>}
{'__module__': 'grr_response_core.lib.parsers.linux_pam_parser', 'ParseMultiple': <function ParseMultiple at 0x7fd0db127de8>, 'output_types': [u'PamConfig'], 'supported_artifacts': [u'LinuxPamConfigs'], '__doc__': u'Artifact parser for PAM configurations.', '__init__': <function __init__ at 0x7fd0db127d70>}
{'__module__': 'grr_response_core.lib.parsers.linux_release_parser', 'ParseMultiple': <function ParseMultiple at 0x7fd0db0b3230>, 'output_types': [u'Dict'], 'WEIGHTS': (WeightedReleaseFile(weight=0, path=u'/etc/lsb-release', processor=<class 'grr_response_core.lib.parsers.linux_release_parser.LsbReleaseParseHandler'>), WeightedReleaseFile(weight=10, path=u'/etc/oracle-release', processor=<grr_response_core.lib.parsers.linux_release_parser.ReleaseFileParseHandler object at 0x7fd0db220ad0>), WeightedReleaseFile(weight=11, path=u'/etc/enterprise-release', processor=<grr_response_core.lib.parsers.linux_release_parser.ReleaseFileParseHandler object at 0x7fd0db0b1b10>), WeightedReleaseFile(weight=20, path=u'/etc/redhat-release', processor=<grr_response_core.lib.parsers.linux_release_parser.ReleaseFileParseHandler object at 0x7fd0db0b1b50>), WeightedReleaseFile(weight=20, path=u'/etc/debian_version', processor=<grr_response_core.lib.parsers.linux_release_parser.ReleaseFileParseHandler object at 0x7fd0db0b1b90>)), 'supported_artifacts': [u'LinuxRelease'], '__doc__': u'Parser for Linux distribution information.', '_Combine': <function _Combine at 0x7fd0db0b31b8>}
{'__module__': 'grr_response_core.lib.parsers.linux_service_parser', 'ParseMultiple': <function ParseMultiple at 0x7fd0db0bf758>, 'output_types': [u'LinuxServiceInformation'], '_ParseInsserv': <function _ParseInsserv at 0x7fd0db0bf6e0>, 'supported_artifacts': [u'LinuxLSBInit'], '_Facilities': <function _Facilities at 0x7fd0db0bf578>, '_ParseInit': <function _ParseInit at 0x7fd0db0bf5f0>, '_InsservExpander': <function _InsservExpander at 0x7fd0db0bf668>, '__doc__': u'Parses LSB style /etc/init.d entries.'}
{'__module__': 'grr_response_core.lib.parsers.linux_service_parser', 'ParseMultiple': <function ParseMultiple at 0x7fd0db0bfb18>, 'output_types': [u'LinuxServiceInformation'], '_ParseSection': <function _ParseSection at 0x7fd0db0bf938>, '_GenService': <function _GenService at 0x7fd0db0bfaa0>, '_ProcessEntries': <function _ProcessEntries at 0x7fd0db0bf9b0>, 'supported_artifacts': [u'LinuxXinetd'], '__doc__': u'Parses xinetd entries.', '_GenConfig': <function _GenConfig at 0x7fd0db0bfa28>}
{'__module__': 'grr_response_core.lib.parsers.linux_service_parser', 'ParseMultiple': <function ParseMultiple at 0x7fd0db0bfcf8>, 'output_types': [u'LinuxServiceInformation'], 'runlevel_re': <_sre.SRE_Pattern object at 0x7fd0db1ed1d8>, 'supported_artifacts': [u'LinuxSysVInit'], '__doc__': u'Parses SysV runlevel entries.\n\n  Reads the stat entries for files under /etc/rc* runlevel scripts.\n  Identifies start and stop levels for services.\n\n  Yields:\n    LinuxServiceInformation for each service with a runlevel entry.\n    Anomalies if there are non-standard service startup definitions.\n  ', 'runscript_re': <_sre.SRE_Pattern object at 0x7fd0db16f580>}
{'__module__': 'grr_response_core.lib.parsers.linux_sysctl_parser', 'ParseMultiple': <function ParseMultiple at 0x7fd0db0c31b8>, 'output_types': [u'AttributedDict'], 'supported_artifacts': [u'LinuxProcSysHardeningSettings'], '_Parse': <function _Parse at 0x7fd0db0c3140>, '__doc__': u'Parser for /proc/sys entries.'}
{'__module__': 'grr_response_core.lib.parsers.linux_sysctl_parser', 'output_types': [u'AttributedDict'], 'Parse': <function Parse at 0x7fd0db0c3410>, 'supported_artifacts': [u'LinuxSysctlCmd'], '__doc__': u'Parser for sysctl -a output.', '__init__': <function __init__ at 0x7fd0db0c3398>}
{'__module__': 'grr_response_core.lib.parsers.osx_file_parser', 'ParseMultiple': <function ParseMultiple at 0x7fd0db0c3c08>, 'output_types': [u'User'], 'blacklist': [u'Shared'], 'supported_artifacts': [u'MacOSUsers'], '__doc__': u'Parser for Glob of /Users/*.'}
{'Parse': <function Parse at 0x7fd0db0e5758>, 'output_types': [u'HardwareInfo'], '__module__': 'grr_response_core.lib.parsers.osx_file_parser', '__doc__': u'Parser for the Hardware Data from System Profiler.', 'supported_artifacts': [u'OSXSPHardwareDataType']}
{'Parse': <function Parse at 0x7fd0db0e5938>, 'output_types': [u'LaunchdPlist'], '__module__': 'grr_response_core.lib.parsers.osx_file_parser', '__doc__': u'Parse Launchd plist files into LaunchdPlist objects.', 'supported_artifacts': [u'MacOSLaunchAgentsPlistFiles', u'MacOSLaunchDaemonsPlistFiles']}
{'Parse': <function Parse at 0x7fd0db0e5b18>, 'output_types': ['SoftwarePackage'], '__module__': 'grr_response_core.lib.parsers.osx_file_parser', '__doc__': u'Parse InstallHistory plist files into SoftwarePackage objects.', 'supported_artifacts': [u'MacOSInstallationHistory']}
{'Parse': <function Parse at 0x7fd0db0e5d70>, 'output_types': [u'PersistenceFile'], '__module__': 'grr_response_core.lib.parsers.osx_launchd', '__doc__': u'Turn various persistence objects into PersistenceFiles.', 'supported_artifacts': [u'DarwinPersistenceMechanisms']}
{'__module__': 'grr_response_core.lib.parsers.windows_persistence', '_GetFilePaths': <function _GetFilePaths at 0x7fd0db0701b8>, 'output_types': [u'PersistenceFile'], 'Parse': <function Parse at 0x7fd0db070230>, 'supported_artifacts': [u'WindowsPersistenceMechanisms'], 'knowledgebase_dependencies': [u'environ_systemdrive', u'environ_systemroot'], '__doc__': u'Turn various persistence objects into PersistenceFiles.'}
{'Parse': <function Parse at 0x7fd0db0e9488>, 'output_types': [u'RDFString'], '__module__': 'grr_response_core.lib.parsers.windows_registry_parser', '__doc__': u'Parser for CurrentControlSet value.', 'supported_artifacts': [u'WindowsRegistryCurrentControlSet', u'CurrentControlSet']}
{'__module__': 'grr_response_core.lib.parsers.windows_registry_parser', 'output_types': [u'RDFString'], 'Parse': <function Parse at 0x7fd0db070500>, 'supported_artifacts': [u'WindowsEnvironmentVariableAllUsersAppData', u'WindowsEnvironmentVariablePath', u'WindowsEnvironmentVariableTemp', u'WindowsEnvironmentVariableWinDir'], 'knowledgebase_dependencies': [u'environ_systemdrive', u'environ_systemroot'], '__doc__': u'Parser for registry retrieved environment variables.'}
{'Parse': <function Parse at 0x7fd0db0706e0>, 'output_types': [u'RDFString'], '__module__': 'grr_response_core.lib.parsers.windows_registry_parser', '__doc__': u'Parser for SystemDrive environment variable.', 'supported_artifacts': [u'WindowsEnvironmentVariableSystemDrive']}
{'Parse': <function Parse at 0x7fd0db0708c0>, 'output_types': [u'RDFString'], '__module__': 'grr_response_core.lib.parsers.windows_registry_parser', '__doc__': u'Parser for SystemRoot environment variables.', 'supported_artifacts': [u'WindowsEnvironmentVariableSystemRoot']}
{'Parse': <function Parse at 0x7fd0db070aa0>, 'output_types': [u'RDFString'], '__module__': 'grr_response_core.lib.parsers.windows_registry_parser', '__doc__': u'Parser for Codepage values.', 'supported_artifacts': [u'WindowsCodePage']}
{'__module__': 'grr_response_core.lib.parsers.windows_registry_parser', 'Parse': <function Parse at 0x7fd0db070c80>, 'supported_artifacts': [u'WindowsEnvironmentVariableProfilesDirectory'], 'knowledgebase_dependencies': [u'environ_systemdrive', u'environ_systemroot'], 'output_type': [u'RDFString'], '__doc__': u'Parser for the ProfilesDirectory environment variable.'}
{'__module__': 'grr_response_core.lib.parsers.windows_registry_parser', 'output_types': [u'RDFString'], 'Parse': <function Parse at 0x7fd0db070e60>, 'supported_artifacts': [u'WindowsEnvironmentVariableAllUsersProfile'], 'knowledgebase_dependencies': [u'environ_profilesdirectory'], '__doc__': u'Parser for AllUsersProfile variable.'}
{'Parse': <function Parse at 0x7fd0db08c0c8>, 'output_types': [u'User'], '__module__': 'grr_response_core.lib.parsers.windows_registry_parser', '__doc__': u'Parser for extracting SID for multiple users.\n\n  This reads a listing of the profile paths to extract a list of SIDS for\n  users with profiles on a system.\n  ', 'supported_artifacts': [u'WindowsRegistryProfiles']}
{'__module__': 'grr_response_core.lib.parsers.windows_registry_parser', 'ParseMultiple': <function ParseMultiple at 0x7fd0db08c2a8>, 'output_types': [u'User'], 'supported_artifacts': [u'WindowsUserShellFolders'], 'knowledgebase_dependencies': [u'environ_systemdrive', u'environ_systemroot', u'users.userprofile'], 'key_var_mapping': {u'Shell Folders': {u'Recent': u'recent', u'Cookies': u'cookies', u'Local AppData': u'localappdata', u'AppData': u'appdata', u'Personal': u'personal', u'Cache': u'internet_cache', u'Startup': u'startup', u'{A520A1A4-1780-4FF6-BD18-167343C5AF16}': u'localappdata_low', u'Desktop': u'desktop'}, u'Environment': {u'TEMP': u'temp'}, u'Volatile Environment': {u'USERDOMAIN': u'userdomain'}}, '__doc__': u"Parser for extracting special folders from registry.\n\n  Keys will come from HKEY_USERS and will list the Shell Folders and user's\n  Environment key. We extract each subkey that matches on of our knowledge base\n  attributes.\n\n  Known folder GUIDs:\n  http://msdn.microsoft.com/en-us/library/windows/desktop/dd378457(v=vs.85).aspx\n  "}
{'__module__': 'grr_response_core.lib.parsers.windows_registry_parser', 'ParseMultiple': <function ParseMultiple at 0x7fd0db08c5f0>, 'output_types': [u'WindowsServiceInformation'], '_GetServiceName': <function _GetServiceName at 0x7fd0db08c500>, 'supported_artifacts': [u'WindowsServices'], '_GetKeyName': <function _GetKeyName at 0x7fd0db08c578>, '__doc__': u'Parser for Windows services values from the registry.\n\n  See service key doco:\n    http://support.microsoft.com/kb/103000\n  ', '__init__': <function __init__ at 0x7fd0db08c488>}
{'Parse': <function Parse at 0x7fd0db08c7d0>, 'output_types': [u'RDFString'], '__module__': 'grr_response_core.lib.parsers.windows_registry_parser', '__doc__': u'Parser for TimeZoneKeyName value.', 'supported_artifacts': [u'WindowsTimezone']}
{'__module__': 'grr_response_core.lib.rdfvalues.wmi', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.WMIActiveScriptEventConsumer'>}
{'__module__': 'grr_response_core.lib.rdfvalues.wmi', 'protobuf': <class 'grr_response_proto.sysinfo_pb2.WMICommandLineEventConsumer'>}
{'Parse': <function Parse at 0x7fd0db030848>, '__module__': 'grr_response_core.lib.parsers.wmi_parser', '_WMIEventConsumerParser__abstract': True, '__doc__': u'Base class for WMI EventConsumer Parsers.'}
{'output_types': ['WMIActiveScriptEventConsumer'], '__module__': 'grr_response_core.lib.parsers.wmi_parser', '__doc__': u'Parser for WMI ActiveScriptEventConsumers.\n\n  https://msdn.microsoft.com/en-us/library/aa384749(v=vs.85).aspx\n  ', 'supported_artifacts': [u'WMIEnumerateASEC']}
{'output_types': ['WMICommandLineEventConsumer'], '__module__': 'grr_response_core.lib.parsers.wmi_parser', '__doc__': u'Parser for WMI CommandLineEventConsumers.\n\n  https://msdn.microsoft.com/en-us/library/aa389231(v=vs.85).aspx\n  ', 'supported_artifacts': [u'WMIEnumerateCLEC']}
{'Parse': <function Parse at 0x7fd0db030cf8>, 'output_types': ['SoftwarePackage'], '__module__': 'grr_response_core.lib.parsers.wmi_parser', '__doc__': u'Parser for WMI output. Yields SoftwarePackage rdfvalues.', 'supported_artifacts': [u'WMIInstalledSoftware']}
{'__module__': 'grr_response_core.lib.parsers.wmi_parser', 'output_types': ['SoftwarePackage'], 'Parse': <function Parse at 0x7fd0db030f50>, 'supported_artifacts': [u'WMIHotFixes'], '__doc__': u'Parser for WMI output. Yields SoftwarePackage rdfvalues.', 'AmericanDateToEpoch': <function AmericanDateToEpoch at 0x7fd0db030ed8>}
{'__module__': 'grr_response_core.lib.parsers.wmi_parser', 'output_types': ['User'], 'Parse': <function Parse at 0x7fd0db0391b8>, 'account_mapping': {u'Domain': u'userdomain', u'LocalPath': u'homedir', u'Name': u'username', u'SID': u'sid'}, '__doc__': u'Parser for WMI Win32_UserAccount and Win32_UserProfile output.', 'supported_artifacts': [u'WMIProfileUsersHomeDir', u'WMIAccountUsersDomain', u'WMIUsers']}
{'Parse': <function Parse at 0x7fd0db039398>, 'output_types': ['Volume'], '__module__': 'grr_response_core.lib.parsers.wmi_parser', '__doc__': u'Parser for LogicalDisk WMI output. Yields Volume rdfvalues.', 'supported_artifacts': [u'WMILogicalDisks']}
{'Parse': <function Parse at 0x7fd0db039578>, 'output_types': ['HardwareInfo'], '__module__': 'grr_response_core.lib.parsers.wmi_parser', '__doc__': u'Parser for WMI Output. Yeilds Identifying Number.', 'supported_artifacts': [u'WMIComputerSystemProduct']}
{'__module__': 'grr_response_core.lib.parsers.wmi_parser', 'output_types': ['Interface', 'DNSClientConfiguration'], 'Parse': <function Parse at 0x7fd0db039848>, 'WMITimeStrToRDFDatetime': <function WMITimeStrToRDFDatetime at 0x7fd0db039758>, 'supported_artifacts': [], '_ConvertIPs': <function _ConvertIPs at 0x7fd0db0397d0>, '__doc__': u'Parser for WMI output. Yields SoftwarePackage rdfvalues.'}
{'__module__': 'grr_response_core.lib.parsers.linux_software_parser', 'output_types': [u'SoftwarePackage'], 'Parse': <function Parse at 0x7fd0db039c80>, 'supported_artifacts': [u'DebianPackagesStatus'], 'installed_re': <_sre.SRE_Pattern object at 0x7fd0db0b04d0>, '__doc__': u'Parser for /var/lib/dpkg/status. Yields SoftwarePackage semantic values.', '__init__': <function __init__ at 0x7fd0db039c08>}
{'__module__': 'grr_response_server.aff4_objects.aff4_queue', 'ReleaseRecords': <classmethod object at 0x7fd0db060b08>, 'RefreshClaims': <function RefreshClaims at 0x7fd0dafeeb90>, 'DeleteRecord': <classmethod object at 0x7fd0db060ad0>, 'StaticAdd': <classmethod object at 0x7fd0db060a60>, 'ReleaseRecord': <classmethod object at 0x7fd0db060b40>, 'Add': <function Add at 0x7fd0dafeea28>, 'DeleteRecords': <classmethod object at 0x7fd0db060a98>, 'ClaimRecords': <function ClaimRecords at 0x7fd0dafeeb18>, '__doc__': u'A queue of messages which can be polled, locked and deleted in bulk.', 'rdf_type': None}
{'__module__': 'grr_response_server.hunts.results', 'ResultRecord': <function ResultRecord at 0x7fd0dafee7d0>, 'protobuf': <class 'grr_response_proto.jobs_pb2.HuntResultNotification'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFDatetime'>, <class 'grr_response_core.lib.rdfvalue.RDFURN'>]}
{'ClaimNotificationsForCollection': <classmethod object at 0x7fd0db060da8>, '__module__': 'grr_response_server.hunts.results', 'DeleteNotifications': <classmethod object at 0x7fd0db060de0>, '__doc__': u'A global queue of hunt results which need to be processed.', 'rdf_type': <class 'grr_response_server.hunts.results.HuntResultNotification'>}
{'pre': [<class 'grr_response_server.aff4.AFF4InitHook'>], '__module__': 'grr_response_server.hunts.results', 'Run': <function Run at 0x7fd0daff4aa0>}
{'ProcessAllReadyRequests': <function ProcessAllReadyRequests at 0x7fd0db0669b0>, '__module__': 'grr_response_server.flow_base', 'End': <function End at 0x7fd0db0662a8>, 'Log': <function Log at 0x7fd0db0668c0>, 'RunStateMethod': <function RunStateMethod at 0x7fd0db066938>, '_ClearAllRequestsAndResponses': <function _ClearAllRequestsAndResponses at 0x7fd0db066758>, 'NotifyAboutEnd': <function NotifyAboutEnd at 0x7fd0db0667d0>, 'CallClient': <function CallClient at 0x7fd0db066488>, 'Start': <function Start at 0x7fd0db066230>, 'IsRunning': <function IsRunning at 0x7fd0db066e60>, '__init__': <function __init__ at 0x7fd0db0661b8>, 'category': u'', 'CallStateInline': <function CallStateInline at 0x7fd0db066410>, 'PersistState': <function PersistState at 0x7fd0daff90c8>, 'state': <property object at 0x7fd0daff0ba8>, 'CallState': <function CallState at 0x7fd0db066398>, 'SendReply': <function SendReply at 0x7fd0db066578>, 'behaviours': <grr_response_server.flow.FlowBehaviour object at 0x7fd0dafeddd0>, 'GetNextOutboundId': <function GetNextOutboundId at 0x7fd0db066aa0>, '__doc__': u'The base class for new style flow objects.', 'GetDefaultArgs': <classmethod object at 0x7fd0db060e88>, 'GetNextResponseId': <function GetNextResponseId at 0x7fd0db066b90>, '_ProcessRepliesWithFlowOutputPlugins': <function _ProcessRepliesWithFlowOutputPlugins at 0x7fd0db066cf8>, 'MergeQueuedMessages': <function MergeQueuedMessages at 0x7fd0db066d70>, '_ProcessRepliesWithHuntOutputPlugins': <function _ProcessRepliesWithHuntOutputPlugins at 0x7fd0db066c80>, 'args': <property object at 0x7fd0daff0c00>, 'NotifyCreatorOfError': <function NotifyCreatorOfError at 0x7fd0db0666e0>, 'SaveResourceUsage': <function SaveResourceUsage at 0x7fd0db0665f0>, 'client_urn': <property object at 0x7fd0daff0b50>, 'client_id': <property object at 0x7fd0daff0af8>, 'Error': <function Error at 0x7fd0db066668>, 'client_os': <property object at 0x7fd0daff0cb0>, 'GetCurrentOutboundId': <function GetCurrentOutboundId at 0x7fd0db066b18>, 'client_knowledge_base': <property object at 0x7fd0daff0d08>, 'MarkDone': <function MarkDone at 0x7fd0db066848>, 'outstanding_requests': <property object at 0x7fd0daff0aa0>, 'ShouldSendNotifications': <function ShouldSendNotifications at 0x7fd0db066de8>, 'args_type': <class 'grr_response_server.flow.EmptyFlowArgs'>, 'friendly_name': None, 'CallFlow': <function CallFlow at 0x7fd0db066500>, 'HeartBeat': <function HeartBeat at 0x7fd0db066320>, 'client_version': <property object at 0x7fd0daff0c58>, 'creator': <property object at 0x7fd0daff0d60>, 'FlushQueuedMessages': <function FlushQueuedMessages at 0x7fd0db066c08>}
{'__module__': 'grr_response_server.artifact', 'protobuf': <class 'grr_response_proto.flows_pb2.KnowledgeBaseInitializationArgs'>}
{}
{}
{'pre': [<class 'grr_response_server.aff4.AFF4InitHook'>], '__module__': 'grr_response_server.artifact', 'RunOnce': <function RunOnce at 0x7fd0db0035f0>, '__doc__': u'Loads artifacts from the datastore and from the filesystem.\n\n  Datastore gets loaded second so it can override Artifacts in the files.\n  '}
{'__module__': 'grr_response_server.flows.general.artifact_fallbacks', 'protobuf': <class 'grr_response_proto.flows_pb2.ArtifactFallbackCollectorArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.artifacts.ArtifactName'>]}
{}
{}
{}
{}
{'__module__': 'grr_response_server.flows.general.transfer', 'protobuf': <class 'grr_response_proto.flows_pb2.GetFileArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>]}
{}
{}
{'__module__': 'grr_response_server.flows.general.transfer', 'protobuf': <class 'grr_response_proto.flows_pb2.MultiGetFileArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.ByteSize'>, <class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>]}
{}
{}
{'ProcessMessages': <function ProcessMessages at 0x7fd0dafc4488>, '__module__': 'grr_response_server.flows.general.transfer', '__doc__': u"Receive an event about a new file and add it to the file store.\n\n  NOTE: this event handles submissions to the LEGACY (AFF4-based) FileStore\n  implementation. For the new REL_DB-based implementation, please see\n  FileStoreCreateFile class below.\n\n  The file store is a central place where files are managed in the data\n  store. Files are deduplicated and stored centrally.\n\n  This event listener will be fired when a new file is downloaded through\n  e.g. the GetFile flow. We then recalculate the file's hashes and store it in\n  the data store under a canonical URN.\n  ", 'EVENTS': [u'LegacyFileStore.AddFileToStore']}
{'__module__': 'grr_response_server.flows.general.transfer', 'protobuf': <class 'grr_response_proto.flows_pb2.GetMBRArgs'>}
{}
{}
{'ProcessMessages': <function ProcessMessages at 0x7fd0dafc4ed8>, '__module__': 'grr_response_server.flows.general.transfer', 'ProcessMessage': <function ProcessMessage at 0x7fd0dafc4f50>, '__doc__': u'Store a buffer into a determined location.', 'well_known_session_id': <aff4:/flows/F:TransferStore age=1970-01-01 00:00:00>}
{}
{}
{'__module__': 'grr_response_server.flows.general.filesystem', 'protobuf': <class 'grr_response_proto.flows_pb2.ListDirectoryArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>]}
{}
{}
{'__module__': 'grr_response_server.flows.general.filesystem', 'protobuf': <class 'grr_response_proto.flows_pb2.RecursiveListDirectoryArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>]}
{}
{}
{'__module__': 'grr_response_server.flows.general.filesystem', 'protobuf': <class 'grr_response_proto.flows_pb2.UpdateSparseImageChunksArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFURN'>]}
{}
{}
{'__module__': 'grr_response_server.flows.general.filesystem', 'protobuf': <class 'grr_response_proto.flows_pb2.FetchBufferForSparseImageArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFURN'>]}
{}
{}
{'__module__': 'grr_response_server.flows.general.filesystem', 'protobuf': <class 'grr_response_proto.flows_pb2.MakeNewAFF4SparseImageArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>]}
{'category': u'/Filesystem/', '__module__': 'grr_response_server.flows.general.filesystem', 'End': <function End at 0x7fd0dafea488>, 'args_type': <class 'grr_response_server.flows.general.filesystem.MakeNewAFF4SparseImageArgs'>, 'Start': <function Start at 0x7fd0dafea398>, '__doc__': u"Gets a new file from the client, possibly as an AFF4SparseImage.\n\n  If the filesize is >= the size threshold, then we get the file as an empty\n  AFF4SparseImage, otherwise we just call GetFile, which gets the complete file.\n\n  We do the check to see if the file is big enough to get as an AFF4SparseImage\n  in this flow so we don't need to do another round trip to the client.\n\n  Args:\n    pathspec: Pathspec of the file to look at.\n    size_threshold: If the file is bigger than this size, we'll get it as an\n      empty AFF4SparseImage, otherwise we'll just download the whole file as\n      usual with GetFile.\n  ", 'ProcessStat': <function ProcessStat at 0x7fd0dafea410>}
{'__module__': 'grr_response_server.flows.general.filesystem', 'Validate': <function Validate at 0x7fd0dafea668>, 'protobuf': <class 'grr_response_proto.flows_pb2.GlobArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.paths.GlobExpression'>, <class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>]}
{}
{}
{'__module__': 'grr_response_server.flows.general.filesystem', 'protobuf': <class 'grr_response_proto.flows_pb2.DiskVolumeInfoArgs'>}
{}
{}
{'__module__': 'grr_response_server.flows.general.fingerprint', 'protobuf': <class 'grr_response_proto.flows_pb2.FingerprintFileArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>]}
{'__module__': 'grr_response_server.flows.general.fingerprint', 'protobuf': <class 'grr_response_proto.flows_pb2.FingerprintFileResult'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.crypto.Hash'>, <class 'grr_response_core.lib.rdfvalue.RDFURN'>]}
{}
{}
{}
{}
{}
{}
{}
{}
{'__module__': 'grr_response_server.flows.general.collectors', 'protobuf': <class 'grr_response_proto.flows_pb2.ArtifactFilesDownloaderFlowArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.artifacts.ArtifactName'>, <class 'grr_response_core.lib.rdfvalue.ByteSize'>]}
{'__module__': 'grr_response_server.flows.general.collectors', 'GetOriginalResultType': <function GetOriginalResultType at 0x7fd0daf8cb18>, 'protobuf': <class 'grr_response_proto.flows_pb2.ArtifactFilesDownloaderResult'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>, <class 'grr_response_core.lib.rdfvalues.client_fs.StatEntry'>]}
{}
{}
{}
{}
{'__module__': 'grr_response_server.export', 'protobuf': <class 'grr_response_proto.export_pb2.ExportOptions'>}
{'__module__': 'grr_response_server.export', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client.ClientURN'>, <class 'grr_response_core.lib.rdfvalues.client.HardwareInfo'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetime'>, <class 'grr_response_core.lib.rdfvalue.RDFURN'>, <class 'grr_response_core.lib.rdfvalue.SessionID'>], '__doc__': u'ExportMetadata RDF value.', '__init__': <function __init__ at 0x7fd0daf9ccf8>, 'protobuf': <class 'grr_response_proto.export_pb2.ExportedMetadata'>}
{'__module__': 'grr_response_server.export', 'protobuf': <class 'grr_response_proto.export_pb2.ExportedClient'>, 'rdf_deps': [<class 'grr_response_server.export.ExportedMetadata'>]}
{'__module__': 'grr_response_server.export', 'protobuf': <class 'grr_response_proto.export_pb2.ExportedFile'>, 'rdf_deps': [<class 'grr_response_server.export.ExportedMetadata'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetimeSeconds'>, <class 'grr_response_core.lib.rdfvalue.RDFURN'>, <class 'grr_response_core.lib.rdfvalues.client_fs.StatMode'>]}
{'__module__': 'grr_response_server.export', 'protobuf': <class 'grr_response_proto.export_pb2.ExportedRegistryKey'>, 'rdf_deps': [<class 'grr_response_server.export.ExportedMetadata'>, <class 'grr_response_core.lib.rdfvalue.RDFDatetimeSeconds'>, <class 'grr_response_core.lib.rdfvalue.RDFURN'>]}
{'__module__': 'grr_response_server.export', 'protobuf': <class 'grr_response_proto.export_pb2.ExportedProcess'>, 'rdf_deps': [<class 'grr_response_server.export.ExportedMetadata'>]}
{'__module__': 'grr_response_server.export', 'protobuf': <class 'grr_response_proto.export_pb2.ExportedNetworkConnection'>, 'rdf_deps': [<class 'grr_response_server.export.ExportedMetadata'>, <class 'grr_response_core.lib.rdfvalues.client_network.NetworkEndpoint'>]}
{'__module__': 'grr_response_server.export', 'protobuf': <class 'grr_response_proto.export_pb2.ExportedDNSClientConfiguration'>, 'rdf_deps': [<class 'grr_response_server.export.ExportedMetadata'>]}
{'__module__': 'grr_response_server.export', 'protobuf': <class 'grr_response_proto.export_pb2.ExportedOpenFile'>, 'rdf_deps': [<class 'grr_response_server.export.ExportedMetadata'>]}
{'__module__': 'grr_response_server.export', 'protobuf': <class 'grr_response_proto.export_pb2.ExportedNetworkInterface'>, 'rdf_deps': [<class 'grr_response_server.export.ExportedMetadata'>]}
{'__module__': 'grr_response_server.export', 'protobuf': <class 'grr_response_proto.export_pb2.ExportedFileStoreHash'>, 'rdf_deps': [<class 'grr_response_server.export.ExportedMetadata'>, <class 'grr_response_core.lib.rdfvalue.RDFURN'>]}
{'__module__': 'grr_response_server.export', 'protobuf': <class 'grr_response_proto.export_pb2.ExportedAnomaly'>}
{'__module__': 'grr_response_server.export', 'protobuf': <class 'grr_response_proto.export_pb2.ExportedCheckResult'>, 'rdf_deps': [<class 'grr_response_server.export.ExportedAnomaly'>, <class 'grr_response_server.export.ExportedMetadata'>]}
{'__module__': 'grr_response_server.export', 'protobuf': <class 'grr_response_proto.export_pb2.ExportedMatch'>, 'rdf_deps': [<class 'grr_response_server.export.ExportedMetadata'>, <class 'grr_response_core.lib.rdfvalue.RDFURN'>]}
{'__module__': 'grr_response_server.export', 'protobuf': <class 'grr_response_proto.export_pb2.ExportedBytes'>, 'rdf_deps': [<class 'grr_response_server.export.ExportedMetadata'>]}
{'__module__': 'grr_response_server.export', 'protobuf': <class 'grr_response_proto.export_pb2.ExportedString'>, 'rdf_deps': [<class 'grr_response_server.export.ExportedMetadata'>]}
{'__module__': 'grr_response_server.export', 'protobuf': <class 'grr_response_proto.export_pb2.ExportedDictItem'>, 'rdf_deps': [<class 'grr_response_server.export.ExportedMetadata'>]}
{'__module__': 'grr_response_server.export', 'protobuf': <class 'grr_response_proto.export_pb2.ExportedArtifactFilesDownloaderResult'>, 'rdf_deps': [<class 'grr_response_server.export.ExportedFile'>, <class 'grr_response_server.export.ExportedMetadata'>, <class 'grr_response_server.export.ExportedRegistryKey'>]}
{'__module__': 'grr_response_server.export', 'protobuf': <class 'grr_response_proto.export_pb2.ExportedYaraProcessScanMatch'>, 'rdf_deps': [<class 'grr_response_server.export.ExportedProcess'>, <class 'grr_response_server.export.ExportedMetadata'>]}
{'Convert': <function Convert at 0x7fd0daf18668>, 'converters_cache': {}, 'input_rdf_type': None, '__module__': 'grr_response_server.export', 'GetConvertersByValue': <staticmethod object at 0x7fd0daf14980>, 'BatchConvert': <function BatchConvert at 0x7fd0daf186e0>, 'GetConvertersByClass': <staticmethod object at 0x7fd0daf14948>, '__doc__': u'Base ExportConverter class.\n\n  ExportConverters are used to convert RDFValues to export-friendly RDFValues.\n  "Export-friendly" means 2 things:\n    * Flat structure\n    * No repeated fields (i.e. lists)\n\n  In order to use ExportConverters, users have to use ConvertValues.\n  These methods will look up all the available ExportConverters descendants\n  and will choose the ones that have input_rdf_type attribute equal to the\n  type of the values being converted. It\'s ok to have multiple converters with\n  the same input_rdf_type value. They will be applied sequentially and their\n  cumulative results will be returned.\n  ', '__init__': <function __init__ at 0x7fd0daf185f0>}
{'__module__': 'grr_response_server.export', '__doc__': u'Special base class for auto-exported values.'}
{'Convert': <function Convert at 0x7fd0daf18c08>, 'ExportedClassNameForValue': <function ExportedClassNameForValue at 0x7fd0daf18b18>, '__module__': 'grr_response_server.export', 'BatchConvert': <function BatchConvert at 0x7fd0daf18c80>, 'MakeFlatRDFClass': <function MakeFlatRDFClass at 0x7fd0daf18b90>, '__doc__': u'Export converter that yields flattened versions of passed values.\n\n  NOTE: DataAgnosticExportConverter discards complex types: repeated\n  fields and nested messages. Only the primitive types (including enums)\n  are preserved.\n  ', 'classes_cache': {}}
{'MAX_CONTENT_SIZE': 65536, '__module__': 'grr_response_server.export', '_ExportFileContent': <function _ExportFileContent at 0x7fd0daf1d140>, '_RemoveRegistryKeys': <function _RemoveRegistryKeys at 0x7fd0daf1d050>, '_BatchConvertLegacy': <function _BatchConvertLegacy at 0x7fd0daf1d230>, 'input_rdf_type': u'StatEntry', '_OpenFilesForRead': <function _OpenFilesForRead at 0x7fd0daf1d0c8>, 'ParseFileHash': <staticmethod object at 0x7fd0daf149f0>, 'ParseSignedData': <staticmethod object at 0x7fd0daf149b8>, '_CreateExportedFile': <function _CreateExportedFile at 0x7fd0daf1d1b8>, 'BatchConvert': <function BatchConvert at 0x7fd0daf1d320>, 'Convert': <function Convert at 0x7fd0daf18f50>, '_BATCH_SIZE': 5000, '__doc__': u'Converts StatEntry to ExportedFile.', '_BatchConvertRelational': <function _BatchConvertRelational at 0x7fd0daf1d2a8>}
{'Convert': <function Convert at 0x7fd0daf1d500>, 'input_rdf_type': u'StatEntry', '__module__': 'grr_response_server.export', '__doc__': u'Converts StatEntry to ExportedRegistryKey.'}
{'Convert': <function Convert at 0x7fd0daf1d6e0>, 'input_rdf_type': u'NetworkConnection', '__module__': 'grr_response_server.export', '__doc__': u'Converts NetworkConnection to ExportedNetworkConnection.'}
{'Convert': <function Convert at 0x7fd0daf1d8c0>, 'input_rdf_type': u'Process', '__module__': 'grr_response_server.export', '__doc__': u'Converts Process to ExportedProcess.'}
{'Convert': <function Convert at 0x7fd0daf1daa0>, 'input_rdf_type': u'Process', '__module__': 'grr_response_server.export', '__doc__': u'Converts Process to ExportedNetworkConnection.'}
{'Convert': <function Convert at 0x7fd0daf1dc80>, 'input_rdf_type': u'Process', '__module__': 'grr_response_server.export', '__doc__': u'Converts Process to ExportedOpenFile.'}
{'Convert': <function Convert at 0x7fd0daf1de60>, '__module__': 'grr_response_server.export', 'input_rdf_type': u'Interface'}
{'Convert': <function Convert at 0x7fd0daf270c8>, '__module__': 'grr_response_server.export', 'input_rdf_type': u'DNSClientConfiguration'}
{'Convert': <function Convert at 0x7fd0daf272a8>, '__module__': 'grr_response_server.export', 'input_rdf_type': u'ClientSummary'}
{'Convert': <function Convert at 0x7fd0daf27488>, '__module__': 'grr_response_server.export', 'input_rdf_type': u'ClientSummary'}
{'Convert': <function Convert at 0x7fd0daf27668>, 'input_rdf_type': u'BufferReference', '__module__': 'grr_response_server.export', '__doc__': u'Export converter for BufferReference instances.'}
{'__module__': 'grr_response_server.export', '_SeparateTypes': <function _SeparateTypes at 0x7fd0daf278c0>, 'input_rdf_type': u'FileFinderResult', 'Convert': <function Convert at 0x7fd0daf279b0>, 'BatchConvert': <function BatchConvert at 0x7fd0daf27938>, '__doc__': u'Export converter for FileFinderResult instances.', '__init__': <function __init__ at 0x7fd0daf27848>}
{'Convert': <function Convert at 0x7fd0daf27b90>, 'input_rdf_type': u'RDFURN', '__module__': 'grr_response_server.export', '__doc__': u'Follows RDFURN and converts its target object into a set of RDFValues.\n\n  Note: This is DEPRECATED due to REL_DB and URN-less world migration.\n\n  TODO(user): remove this as soon as REL_DB becomes the main implementation\n  and URNs are gone.\n  ', 'BatchConvert': <function BatchConvert at 0x7fd0daf27c08>}
{'Convert': <function Convert at 0x7fd0daf27de8>, '__module__': 'grr_response_server.export', 'input_rdf_type': None, 'BATCH_SIZE': 1000}
{'__module__': 'grr_response_server.export', 'input_rdf_type': u'GrrMessageCollection'}
{'__module__': 'grr_response_server.export', 'input_rdf_type': u'HuntResultCollection'}
{'__module__': 'grr_response_server.export', 'input_rdf_type': u'FlowResultCollection'}
{'Convert': <function Convert at 0x7fd0daeaf410>, '__module__': 'grr_response_server.export', 'input_rdf_type': u'VFSFile'}
{'Convert': <function Convert at 0x7fd0daeaf5f0>, '__module__': 'grr_response_server.export', 'input_rdf_type': u'RDFBytes'}
{'Convert': <function Convert at 0x7fd0daeaf7d0>, '__module__': 'grr_response_server.export', 'input_rdf_type': u'RDFString'}
{'Convert': <function Convert at 0x7fd0daeafa28>, 'input_rdf_type': u'Dict', '__module__': 'grr_response_server.export', '__doc__': u'Export converter that converts Dict to ExportedDictItems.', '_IterateDict': <function _IterateDict at 0x7fd0daeaf9b0>}
{'Convert': <function Convert at 0x7fd0daeafc80>, 'input_rdf_type': u'GrrMessage', '__module__': 'grr_response_server.export', 'BatchConvert': <function BatchConvert at 0x7fd0daeafcf8>, '__doc__': u'Converts GrrMessage\'s payload into a set of RDFValues.\n\n  GrrMessageConverter converts given GrrMessages to a set of exportable\n  RDFValues. It looks at the payload of every message and applies necessary\n  converters to produce the resulting RDFValues.\n\n  Usually, when a value is converted via one of the ExportConverter classes,\n  metadata (ExportedMetadata object describing the client, session id, etc)\n  are provided by the caller. But when converting GrrMessages, the caller can\'t\n  provide any reasonable metadata. In order to understand where the messages\n  are coming from, one actually has to inspect the messages source and this\n  is done by GrrMessageConverter and not by the caller.\n\n  Although ExportedMetadata should still be provided for the conversion to\n  happen, only "source_urn" and value will be used. All other metadata will be\n  fetched from the client object pointed to by GrrMessage.source.\n  ', '__init__': <function __init__ at 0x7fd0daeafc08>}
{'Convert': <function Convert at 0x7fd0daeafed8>, 'BatchConvert': <function BatchConvert at 0x7fd0daeaff50>, '__module__': 'grr_response_server.export', 'input_rdf_type': u'FileStoreHash'}
{'Convert': <function Convert at 0x7fd0daeb81b8>, '__module__': 'grr_response_server.export', 'input_rdf_type': u'CheckResult'}
{'__module__': 'grr_response_server.export', 'input_rdf_type': 'ArtifactFilesDownloaderResult', 'GetExportedResult': <function GetExportedResult at 0x7fd0daeb8398>, 'Convert': <function Convert at 0x7fd0daeb8578>, 'BatchConvert': <function BatchConvert at 0x7fd0daeb8500>, 'IsRegistryStatEntry': <function IsRegistryStatEntry at 0x7fd0daeb8410>, 'IsFileStatEntry': <function IsFileStatEntry at 0x7fd0daeb8488>, '__doc__': u'Converts ArtifactFilesDownloaderResult to its exported version.'}
{'Convert': <function Convert at 0x7fd0daeb8758>, '__module__': 'grr_response_server.export', 'input_rdf_type': u'YaraProcessScanMatch'}
{'RetrieveIPInfo': <function RetrieveIPInfo at 0x7fd0daeb8de8>, '__module__': 'grr_response_server.ip_resolver'}
{'__module__': 'grr_response_server.ip_resolver', 'RetrieveIPInfo': <function RetrieveIPInfo at 0x7fd0daef90c8>, 'RetrieveIP4Info': <function RetrieveIP4Info at 0x7fd0daef9140>, 'RetrieveIP6Info': <function RetrieveIP6Info at 0x7fd0daef91b8>, '__doc__': u'Resolves IP addresses to hostnames.', '__init__': <function __init__ at 0x7fd0daef9050>}
{'__module__': 'grr_response_server.ip_resolver', 'RunOnce': <function RunOnce at 0x7fd0daef9398>}
{'__module__': 'grr_response_server.master', 'IsMaster': <function IsMaster at 0x7fd0daef96e0>, 'is_master': True, 'SetMaster': <function SetMaster at 0x7fd0daef9758>, '__doc__': u'A Master Watcher that always returns True.', '__init__': <function __init__ at 0x7fd0daef9668>}
{'__module__': 'grr_response_server.master', 'RunOnce': <function RunOnce at 0x7fd0daef9938>, '__doc__': u'Init hook class for the master watcher.'}
{'__module__': 'grr_response_server.output_plugins.bigquery_plugin', 'protobuf': <class 'grr_response_proto.output_plugin_pb2.BigQueryOutputPluginArgs'>, 'rdf_deps': [<class 'grr_response_server.export.ExportOptions'>]}
{'_GetTempOutputFileHandles': <function _GetTempOutputFileHandles at 0x7fd0da86e050>, '__module__': 'grr_response_server.output_plugins.bigquery_plugin', 'description': u'Send output to bigquery.', 'RDF_BIGQUERY_TYPE_MAP': {u'uint64': u'INTEGER', u'float': u'FLOAT', u'bool': u'BOOLEAN', u'uint32': u'INTEGER'}, '_CreateOutputFileHandles': <function _CreateOutputFileHandles at 0x7fd0da868f50>, '_WriteJSONValue': <function _WriteJSONValue at 0x7fd0da868ed8>, 'args_type': <class 'grr_response_server.output_plugins.bigquery_plugin.BigQueryOutputPluginArgs'>, 'UpdateState': <function UpdateState at 0x7fd0da868d70>, 'WriteValuesToJSONFile': <function WriteValuesToJSONFile at 0x7fd0da86e230>, '_GetNestedDict': <function _GetNestedDict at 0x7fd0da868e60>, 'RDFValueToBigQuerySchema': <function RDFValueToBigQuerySchema at 0x7fd0da86e140>, '__init__': <function __init__ at 0x7fd0da868c80>, 'Flush': <function Flush at 0x7fd0da86e0c8>, 'InitializeState': <function InitializeState at 0x7fd0da868cf8>, 'ProcessResponses': <function ProcessResponses at 0x7fd0da868de8>, '__doc__': u'Output plugin that uploads hunt results to BigQuery.\n\n  We write gzipped JSON data and a BigQuery schema to temporary files. One file\n  for each output type is created during ProcessResponses, then we upload the\n  data and schema to BigQuery during Flush. On failure we retry a few times.\n\n  We choose JSON output for BigQuery so we can support simply export fields that\n  contain newlines, including when users choose to export file content. This is\n  a bigquery recommendation for performance:\n  https://cloud.google.com/bigquery/preparing-data-for-bigquery?hl=en\n  ', 'GZIP_COMPRESSION_LEVEL': 9, 'name': u'bigquery'}
{'__module__': 'grr_response_server.instant_output_plugin', 'output_file_extension': u'', 'description': None, 'ProcessValues': <function ProcessValues at 0x7fd0da875140>, '_InstantOutputPlugin__abstract': True, 'friendly_name': None, 'GetPluginClassByPluginName': <classmethod object at 0x7fd0da86ca98>, 'plugin_name': None, 'Start': <function Start at 0x7fd0da8750c8>, 'Finish': <function Finish at 0x7fd0da8751b8>, 'output_file_name': <property object at 0x7fd0da873208>, '__doc__': u'The base class for instant output plugins.\n\n  Instant output plugins do on-the-fly data conversion and are used in\n  GetExportedFlowResults/GetExportedHuntResults methods.\n  ', '__init__': <function __init__ at 0x7fd0da86ef50>}
{'__module__': 'grr_response_server.instant_output_plugin', 'ProcessSingleTypeExportedValues': <function ProcessSingleTypeExportedValues at 0x7fd0da875500>, 'GetExportOptions': <function GetExportOptions at 0x7fd0da875488>, '_InstantOutputPluginWithExportConversion__abstract': True, 'BATCH_SIZE': 5000, '_GetMetadataForClients': <function _GetMetadataForClients at 0x7fd0da875410>, 'ProcessValues': <function ProcessValues at 0x7fd0da875668>, '_GenerateSingleTypeIteration': <function _GenerateSingleTypeIteration at 0x7fd0da875578>, '_GenerateConvertedValues': <function _GenerateConvertedValues at 0x7fd0da8755f0>, '__doc__': u'Instant output plugin that flattens data before exporting.', '__init__': <function __init__ at 0x7fd0da875398>}
{'__module__': 'grr_response_server.output_plugins.csv_plugin', 'output_file_extension': u'.zip', 'description': u'Output ZIP archive with CSV files.', '_GetCSVRow': <function _GetCSVRow at 0x7fd0da8759b0>, '_GetCSVHeader': <function _GetCSVHeader at 0x7fd0da875938>, 'friendly_name': u'CSV (zipped)', 'plugin_name': u'csv-zip', 'Start': <function Start at 0x7fd0da875aa0>, 'ProcessSingleTypeExportedValues': <function ProcessSingleTypeExportedValues at 0x7fd0da875b18>, 'ROW_BATCH': 100, 'path_prefix': <property object at 0x7fd0da8735d0>, '__doc__': u'Instant Output plugin that writes results to an archive of CSV files.', 'Finish': <function Finish at 0x7fd0da875b90>}
{'__module__': 'grr_response_server.email_alerts', 'SendEmail': <function SendEmail at 0x7fd0da564b18>, 'AddEmailDomain': <function AddEmailDomain at 0x7fd0da564a28>, 'SplitEmailsAndAppendEmailDomain': <function SplitEmailsAndAppendEmailDomain at 0x7fd0da564aa0>, 'RemoveHtmlTags': <function RemoveHtmlTags at 0x7fd0da5649b0>, '__doc__': u'The email alerter base class.'}
{'__module__': 'grr_response_server.email_alerts', 'SendEmail': <function SendEmail at 0x7fd0da564cf8>}
{'__module__': 'grr_response_server.email_alerts', 'RunOnce': <function RunOnce at 0x7fd0da564ed8>}
{'__module__': 'grr_response_server.output_plugins.email_plugin', 'protobuf': <class 'grr_response_proto.output_plugin_pb2.EmailOutputPluginArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.standard.DomainEmailAddress'>]}
{'__module__': 'grr_response_server.output_plugins.email_plugin', 'description': u'Send an email for each result.', 'InitializeState': <function InitializeState at 0x7fd0da5678c0>, 'args_type': <class 'grr_response_server.output_plugins.email_plugin.EmailOutputPluginArgs'>, 'ProcessResponse': <function ProcessResponse at 0x7fd0da567a28>, 'UpdateState': <function UpdateState at 0x7fd0da567b18>, 'IncrementCounter': <function IncrementCounter at 0x7fd0da5679b0>, 'produces_output_streams': False, 'template': <Template memory:7fd0da5e1c10>, 'too_many_mails_msg': u'<p> This hunt has now produced %d results so the sending of emails will be disabled now. </p>', 'subject_template': <Template memory:7fd0da5e1bd0>, 'ProcessResponses': <function ProcessResponses at 0x7fd0da567aa0>, '__doc__': u'An output plugin that sends an email for each response received.', '__init__': <function __init__ at 0x7fd0da5677d0>, 'name': u'email'}
{'_ConvertToCanonicalSqlDict': <function _ConvertToCanonicalSqlDict at 0x7fd0da57be60>, '__module__': 'grr_response_server.output_plugins.sqlite_plugin', 'output_file_extension': u'.zip', '_GetSqliteSchema': <function _GetSqliteSchema at 0x7fd0da57bd70>, 'description': u'Output ZIP archive containing SQLite scripts.', '_InsertValueIntoDb': <function _InsertValueIntoDb at 0x7fd0da57bde8>, 'friendly_name': u'SQLite scripts (zipped)', 'plugin_name': u'sqlite-zip', 'Start': <function Start at 0x7fd0da57bc80>, 'ProcessSingleTypeExportedValues': <function ProcessSingleTypeExportedValues at 0x7fd0da57bcf8>, 'ROW_BATCH': 100, '_FlushAllRows': <function _FlushAllRows at 0x7fd0da57bed8>, 'path_prefix': <property object at 0x7fd0da590aa0>, 'Finish': <function Finish at 0x7fd0da57bf50>, '__doc__': u'Instant output plugin that converts results into SQLite db commands.', '__init__': <function __init__ at 0x7fd0da57bb90>}
{'__module__': 'grr_response_server.output_plugins.yaml_plugin', 'output_file_extension': u'.zip', 'description': u'Output ZIP archive with YAML files (flattened).', 'friendly_name': u'Flattened YAML (zipped)', 'plugin_name': u'flattened-yaml-zip', 'Start': <function Start at 0x7fd0da586578>, 'ProcessSingleTypeExportedValues': <function ProcessSingleTypeExportedValues at 0x7fd0da5865f0>, 'ROW_BATCH': 100, 'path_prefix': <property object at 0x7fd0da590d60>, 'Finish': <function Finish at 0x7fd0da586668>, '__doc__': u'Instant output plugin that flattens results into YAML.', '__init__': <function __init__ at 0x7fd0da586488>}
{'__module__': 'grr_response_server.stats_server', 'RunOnce': <function RunOnce at 0x7fd0d9ddd0c8>, '__doc__': u'Starts up a varz server after everything is registered.'}
{'__module__': 'grr_response_server.aff4_objects.collects', 'Read': <function Read at 0x7fd0d9ddd758>, '__iter__': <function __iter__ at 0x7fd0d9ddd848>, 'collection': None, 'Tell': <function Tell at 0x7fd0d9ddd938>, 'Write': <function Write at 0x7fd0d9ddd6e0>, 'Add': <function Add at 0x7fd0d9ddd7d0>, '_EnsureInitialized': <function _EnsureInitialized at 0x7fd0d9ddd668>, 'chunks': <property object at 0x7fd0d9dda418>, 'OnDelete': <function OnDelete at 0x7fd0d9ddda28>, 'NewFromContent': <classmethod object at 0x7fd0d9dcc6a8>, 'Seek': <function Seek at 0x7fd0d9ddd9b0>, '__doc__': u'A container for storing a signed binary blob such as a driver.', '__len__': <function __len__ at 0x7fd0d9ddd8c0>, 'size': <property object at 0x7fd0d9dda470>}
{'__module__': 'grr_response_server.cronjobs', 'Run': <function Run at 0x7fd0d9df3230>, '_CronJobBase__abstract': True, '__metaclass__': <class 'grr_response_core.lib.registry.CronJobRegistry'>, 'StartRun': <function StartRun at 0x7fd0d9df32a8>, '__doc__': u'The base class for all cron jobs.', '__init__': <function __init__ at 0x7fd0d9df31b8>}
{'__module__': 'grr_response_server.cronjobs', '__metaclass__': <class 'grr_response_core.lib.registry.SystemCronJobRegistry'>, 'Log': <function Log at 0x7fd0d9df3578>, 'allow_overruns': False, 'WriteCronState': <function WriteCronState at 0x7fd0d9df3668>, 'enabled': True, '_SystemCronJobBase__abstract': True, 'frequency': None, 'HeartBeat': <function HeartBeat at 0x7fd0d9df3500>, 'lifetime': None, 'ReadCronState': <function ReadCronState at 0x7fd0d9df35f0>, '__doc__': u'The base class for all system cron jobs.', '__init__': <function __init__ at 0x7fd0d9df3488>}
{'__module__': 'grr_response_server.aff4_objects.cronjobs', '_SystemCronFlow__abstract': True, 'allow_overruns': False, 'enabled': True, 'disabled': <property object at 0x7fd0df8e44c8>, '_ValidateState': <function _ValidateState at 0x7fd0dcf969b0>, 'frequency': <Duration('1d')>, 'lifetime': <Duration('20h')>, '__doc__': u'SystemCronFlows are scheduled automatically on workers startup.'}
{'__module__': 'grr_response_server.aff4_objects.cronjobs', 'WriteCronState': <function WriteCronState at 0x7fd0d9dfbaa0>, 'cron_job_urn': <property object at 0x7fd0d9df6940>, '_StatefulSystemCronFlow__abstract': True, 'ReadCronState': <function ReadCronState at 0x7fd0d9dfba28>, '__doc__': u'SystemCronFlow that keeps a permanent state between iterations.'}
{'__module__': 'grr_response_server.aff4_objects.cronjobs', 'IsRunning': <function IsRunning at 0x7fd0d9dfbed8>, 'SchemaCls': <class 'grr_response_server.aff4_objects.cronjobs.SchemaCls'>, 'StopCurrentRun': <function StopCurrentRun at 0x7fd0d9b7d050>, 'DueToRun': <function DueToRun at 0x7fd0d9dfbf50>, 'Run': <function Run at 0x7fd0d9b7d140>, 'KillOldFlows': <function KillOldFlows at 0x7fd0d9b7d0c8>, '__doc__': u'AFF4 object corresponding to cron jobs.'}
{'pre': [<class 'grr_response_server.aff4.AFF4InitHook'>, <class 'grr_response_server.master.MasterInit'>], '__module__': 'grr_response_server.aff4_objects.cronjobs', 'RunOnce': <function RunOnce at 0x7fd0d9b7d320>, '__doc__': u'Init hook for cron job metrics.'}
{'AuthorizeGroup': <function AuthorizeGroup at 0x7fd0d9b93aa0>, '__module__': 'grr_response_server.authorization.groups', 'MemberOfAuthorizedGroup': <function MemberOfAuthorizedGroup at 0x7fd0d9b93b18>, '_GroupAccessManager__abstract': True}
{'AuthorizeGroup': <function AuthorizeGroup at 0x7fd0d9b93cf8>, '__module__': 'grr_response_server.authorization.groups', 'MemberOfAuthorizedGroup': <function MemberOfAuthorizedGroup at 0x7fd0d9b93d70>, '__doc__': u"Placeholder class for enabling group ACLs.\n\n  By default GRR doesn't have the concept of groups. To add it, override this\n  class with a module in lib/local/groups.py that inherits from the same\n  superclass. This class should be able to check group membership in whatever\n  system you use: LDAP/AD/etc.\n  "}
{'key': <property object at 0x7fd0d9b9b260>, '__module__': 'grr_response_server.authorization.client_approval_auth', 'users': <property object at 0x7fd0d9b9b310>, 'label': <property object at 0x7fd0d9b9b2b8>, 'groups': <property object at 0x7fd0d9b9b368>, '__doc__': u'Authorization to approve clients with a particular label.', 'protobuf': <class 'grr_response_proto.acls_pb2.ClientApprovalAuthorization'>}
{'__module__': 'grr_response_server.authorization.client_approval_auth', 'RunOnce': <function RunOnce at 0x7fd0d9ba32a8>}
{'__module__': 'grr_response_server.aff4_objects.security', 'GetApprovalForObject': <staticmethod object at 0x7fd0d9deefd8>, '__doc__': u"An abstract approval request object.\n\n  This object normally lives within the namespace:\n  aff4:/ACL/...\n\n  The aff4:/ACL namespace is not writable by users, hence all manipulation of\n  this object must be done via dedicated flows. These flows use the server's\n  access credentials for manipulating this object.\n  ", 'SchemaCls': <class 'grr_response_server.aff4_objects.security.SchemaCls'>, 'CheckAccess': <function CheckAccess at 0x7fd0d9ba3488>}
{'__module__': 'grr_response_server.aff4_objects.security', 'min_approvers_with_label': 1, 'SchemaCls': <class 'grr_response_server.aff4_objects.security.SchemaCls'>, 'checked_approvers_label': None, 'GetApprovers': <function GetApprovers at 0x7fd0d9ba3758>, 'GetNonExpiredApprovers': <function GetNonExpiredApprovers at 0x7fd0d9ba3848>, 'CheckAccess': <function CheckAccess at 0x7fd0d9ba37d0>, '__doc__': u"Generic all-purpose base approval class.\n\n  This object normally lives within the aff4:/ACL namespace. Username is\n  encoded into this object's urn. Subject's urn (i.e. urn of the object\n  which this approval corresponds for) can also be inferred from this approval's\n  urn.\n  This class provides following functionality:\n  * Number of approvers configured by ACL.approvers_required configuration\n    parameter is required for this approval's CheckAccess() to succeed.\n  * Optional checked_approvers_label attribute may be specified. Then\n    at least min_approvers_with_label number of approvers will have to\n    have checked_approvers_label label in order for CheckAccess to\n    succeed.\n  * Break-glass functionality. If this approval's BREAK_GLASS attribute is\n    set, user's token is marked as emergency token and CheckAccess() returns\n    True.\n\n  The aff4:/ACL namespace is not writable by users, hence all manipulation of\n  this object must be done via dedicated flows.\n  ", 'InferUserAndSubjectFromUrn': <function InferUserAndSubjectFromUrn at 0x7fd0d9ba36e0>}
{'__module__': 'grr_response_server.aff4_objects.security', '__doc__': u"An approval request for access to a specific client.\n\n  This object normally lives within the namespace:\n  aff4:/ACL/client_id/user/approval:<id>\n\n  Hence the client_id and user which is granted access are inferred from this\n  object's URN.\n  ", 'CheckAccess': <function CheckAccess at 0x7fd0d9ba3a28>, 'InferUserAndSubjectFromUrn': <function InferUserAndSubjectFromUrn at 0x7fd0d9ba39b0>}
{'checked_approvers_label': u'admin', '__module__': 'grr_response_server.aff4_objects.security', '__doc__': u"An approval request for running a specific hunt.\n\n  This object normally lives within the namespace:\n  aff4:/ACL/hunts/hunt_id/user_id/approval:<id>\n\n  Hence the hunt_id and user_id are inferred from this object's URN.\n  ", 'InferUserAndSubjectFromUrn': <function InferUserAndSubjectFromUrn at 0x7fd0d9ba3c08>}
{'checked_approvers_label': u'admin', '__module__': 'grr_response_server.aff4_objects.security', '__doc__': u"An approval request for managing a specific cron job.\n\n  This object normally lives within the namespace:\n  aff4:/ACL/cron/cron_job_id/user_id/approval:<id>\n\n  Hence the hunt_id and user_id are inferred from this object's URN.\n  ", 'InferUserAndSubjectFromUrn': <function InferUserAndSubjectFromUrn at 0x7fd0d9ba3de8>}
{'__module__': 'grr_response_server.aff4_objects.stats', '__doc__': u'A container for all client statistics.', 'SchemaCls': <class 'grr_response_server.aff4_objects.stats.SchemaCls'>}
{'__module__': 'grr_response_server.aff4_objects.stats', '__doc__': u'AFF4 object for storing client statistics.', 'SchemaCls': <class 'grr_response_server.aff4_objects.stats.SchemaCls'>}
{'_UserHasAdminLabel': <function _UserHasAdminLabel at 0x7fd0d9bb55f0>, '__module__': 'grr_response_server.aff4_objects.user_managers', '_CheckAccessWithHelpers': <function _CheckAccessWithHelpers at 0x7fd0d9bb5848>, '_CheckApprovalsForTokenWithoutReason': <function _CheckApprovalsForTokenWithoutReason at 0x7fd0d9bb58c0>, 'CLIENT_URN_PATTERN': u'aff4:/C.[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]', 'CheckHuntAccess': <function CheckHuntAccess at 0x7fd0d9bb5c08>, '_CreateQueryAccessHelper': <function _CreateQueryAccessHelper at 0x7fd0d9bb57d0>, '_CreateReadAccessHelper': <function _CreateReadAccessHelper at 0x7fd0d9bb5758>, '_CreateWriteAccessHelper': <function _CreateWriteAccessHelper at 0x7fd0d9bb56e0>, 'approval_cache_time': 600, '_CheckApprovals': <function _CheckApprovals at 0x7fd0d9bb5938>, 'CheckIfCanStartFlow': <function CheckIfCanStartFlow at 0x7fd0d9bb5ed8>, 'CheckDataStoreAccess': <function CheckDataStoreAccess at 0x7fd0d9bb90c8>, '_IsHomeDir': <function _IsHomeDir at 0x7fd0d9bb5668>, 'CheckClientAccess': <function CheckClientAccess at 0x7fd0d9bb5aa0>, '_HasAccessToClient': <function _HasAccessToClient at 0x7fd0d9bb5578>, '__doc__': u'Control read/write/query access for multi-party authorization system.\n\n  This access control manager enforces valid identity and a scheme of\n  read/write/query access that works with the GRR approval system.\n  ', '__init__': <function __init__ at 0x7fd0d9bb5500>, 'CheckCronJobAccess': <function CheckCronJobAccess at 0x7fd0d9bb5d70>}
{'DeleteAttributes': <function DeleteAttributes at 0x7fd0d9b3f938>, 'ClearTestDB': <function ClearTestDB at 0x7fd0d9b3f5f0>, 'Set': <function Set at 0x7fd0d9b3f758>, 'PrintSubjects': <function PrintSubjects at 0x7fd0d9b3fe60>, 'ResolvePrefix': <function ResolvePrefix at 0x7fd0d9b3fd70>, '__module__': 'grr_response_server.data_stores.fake_data_store', 'ScanAttributes': <function ScanAttributes at 0x7fd0d9b3fa28>, 'MultiResolvePrefix': <function MultiResolvePrefix at 0x7fd0d9b3fc08>, 'DeleteSubject': <function DeleteSubject at 0x7fd0d9b3f500>, '__init__': <function __init__ at 0x7fd0d9b3f410>, 'Flush': <function Flush at 0x7fd0d9b3fc80>, 'MultiSet': <function MultiSet at 0x7fd0d9b3f848>, 'Size': <function Size at 0x7fd0d9b3fde8>, '__doc__': u'A fake data store - Everything is in memory.', 'DBSubjectLock': <function DBSubjectLock at 0x7fd0d9b3f668>, 'ResolveMulti': <function ResolveMulti at 0x7fd0d9b3fb18>}
{'__module__': 'grr_response_server.data_stores.mysql_advanced_data_store', '_BuildDelete': <function _BuildDelete at 0x7fd0d9b5ce60>, 'DBSubjectLock': <function DBSubjectLock at 0x7fd0d9b5c320>, 'MultiSet': <function MultiSet at 0x7fd0d9b5c758>, '_CountExistingRows': <function _CountExistingRows at 0x7fd0d9b5c7d0>, '_RetryWrapper': <function _RetryWrapper at 0x7fd0d9b5caa0>, '_BuildReplaces': <function _BuildReplaces at 0x7fd0d9b5c938>, '_Decode': <function _Decode at 0x7fd0d9b5cd70>, 'ExecuteQuery': <function ExecuteQuery at 0x7fd0d9b5cb18>, '_Encode': <function _Encode at 0x7fd0d9b5ccf8>, 'ScanAttributes': <function ScanAttributes at 0x7fd0d9b5c6e0>, 'MultiResolvePrefix': <function MultiResolvePrefix at 0x7fd0d9b5c578>, '_BuildInserts': <function _BuildInserts at 0x7fd0d9b5ca28>, '__init__': <function __init__ at 0x7fd0d9b65f50>, 'Initialize': <function Initialize at 0x7fd0d9b5c050>, '__doc__': u'A mysql based data store.', 'DeleteSubject': <function DeleteSubject at 0x7fd0d9b5c488>, 'ResolveMulti': <function ResolveMulti at 0x7fd0d9b5c500>, 'DeleteAttributes': <function DeleteAttributes at 0x7fd0d9b5c410>, '_BuildAff4InsertQuery': <function _BuildAff4InsertQuery at 0x7fd0d9b5c9b0>, '_MakeTimestamp': <function _MakeTimestamp at 0x7fd0d9b5ced8>, 'ClearTestDB': <function ClearTestDB at 0x7fd0d9b5c140>, '_BuildQuery': <function _BuildQuery at 0x7fd0d9b5cde8>, 'RecreateTables': <function RecreateTables at 0x7fd0d9b5c2a8>, '_ExecuteTransaction': <function _ExecuteTransaction at 0x7fd0d9b5cc08>, 'POOL': None, '_ExecuteQueries': <function _ExecuteQueries at 0x7fd0d9b5cb90>, 'SetupTestDB': <classmethod object at 0x7fd0d9b43ef8>, 'DestroyTestDB': <function DestroyTestDB at 0x7fd0d9b5c1b8>, '_CreateTables': <function _CreateTables at 0x7fd0d9b5cf50>, '_ScanAttribute': <function _ScanAttribute at 0x7fd0d9b5c668>, '_CalculateAttributeStorageTypes': <function _CalculateAttributeStorageTypes at 0x7fd0d9b5cc80>, 'ResolvePrefix': <function ResolvePrefix at 0x7fd0d9b5c5f0>, 'Flush': <function Flush at 0x7fd0d9b5c8c0>, 'DropTables': <function DropTables at 0x7fd0d9b5c230>, 'Size': <function Size at 0x7fd0d9b5c398>}
{'AddKeywordsForName': <function AddKeywordsForName at 0x7fd0d9b6e500>, '__module__': 'grr_response_server.keyword_index', 'LAST_TIMESTAMP': 9223372036854775806L, '__doc__': u'An index linking keywords to names of objects.\n  ', 'Lookup': <function Lookup at 0x7fd0d9b6e410>, 'RemoveKeywordsForName': <function RemoveKeywordsForName at 0x7fd0d9b6e578>, 'FIRST_TIMESTAMP': 0, 'ReadPostingLists': <function ReadPostingLists at 0x7fd0d9b6e488>}
{'__module__': 'grr_response_server.client_index', '_NormalizeKeyword': <function _NormalizeKeyword at 0x7fd0d9b6e7d0>, '_AnalyzeKeywords': <function _AnalyzeKeywords at 0x7fd0d9b6e848>, 'LookupClients': <function LookupClients at 0x7fd0d9b6e8c0>, '_ClientIdFromURN': <function _ClientIdFromURN at 0x7fd0d9b6e758>, 'START_TIME_PREFIX_LEN': 11, 'END_TIME_PREFIX': u'end_date:', 'AddClient': <function AddClient at 0x7fd0d9b6ea28>, 'ReadClientPostingLists': <function ReadClientPostingLists at 0x7fd0d9b6e938>, 'RemoveClientLabels': <function RemoveClientLabels at 0x7fd0d9b6eaa0>, 'START_TIME_PREFIX': u'start_date:', 'END_TIME_PREFIX_LEN': 9, 'AnalyzeClient': <function AnalyzeClient at 0x7fd0d9b6e9b0>, '__doc__': u'An index of client machines.'}
{'__module__': 'grr_response_server.hunts.implementation', '__doc__': u'Metadata AFF4 object used by CronHuntOutputFlow.', 'SchemaCls': <class 'grr_response_server.hunts.implementation.SchemaCls'>}
{'GetClientStates': <function GetClientStates at 0x7fd0d9b1cde8>, 'all_clients_collection_urn': <property object at 0x7fd0d9b07cb0>, '__module__': 'grr_response_server.hunts.implementation', 'RunClient': <function RunClient at 0x7fd0d9b1c398>, 'CompletedClientsCollectionForHID': <classmethod object at 0x7fd0d9b13520>, 'creator': <property object at 0x7fd0d9b07e10>, 'ProcessClientResourcesStats': <function ProcessClientResourcesStats at 0x7fd0d9b1cb18>, 'clients_errors_collection_urn': <property object at 0x7fd0d9b07b50>, 'OnDelete': <function OnDelete at 0x7fd0d9b1c320>, 'GetCompletedClients': <function GetCompletedClients at 0x7fd0d9b1ccf8>, 'PluginStatusCollectionForHID': <classmethod object at 0x7fd0d9b13440>, 'TypedResultCollectionForHID': <classmethod object at 0x7fd0d9b13328>, 'Start': <function Start at 0x7fd0d9b1c8c0>, 'Pause': <function Pause at 0x7fd0d9b1c500>, 'ResultCollectionForHID': <classmethod object at 0x7fd0d9b132f0>, 'ClientsWithResultsCollection': <function ClientsWithResultsCollection at 0x7fd0d9b1ab90>, 'logs_collection_urn': <property object at 0x7fd0d9b07af8>, '_SetupOutputPluginState': <function _SetupOutputPluginState at 0x7fd0d9b1c938>, 'WriteState': <function WriteState at 0x7fd0d9b1cf50>, 'RegisterClientError': <function RegisterClientError at 0x7fd0d9b1c2a8>, '_AddHuntErrorToCollection': <function _AddHuntErrorToCollection at 0x7fd0d9b1c050>, 'Save': <function Save at 0x7fd0d9b1ce60>, 'Run': <function Run at 0x7fd0d9b1c488>, 'TypedResultCollection': <function TypedResultCollection at 0x7fd0d9b1a488>, 'LogClientError': <function LogClientError at 0x7fd0d9b1caa0>, 'CreateCollections': <function CreateCollections at 0x7fd0d9b1c9b0>, 'Stop': <function Stop at 0x7fd0d9b1c578>, 'RegisterClientWithResults': <function RegisterClientWithResults at 0x7fd0d9b1c230>, 'ResultCollection': <function ResultCollection at 0x7fd0d9b1a320>, 'ClientsWithResultsCollectionForHID': <classmethod object at 0x7fd0d9b134b0>, 'RegisterCrash': <function RegisterCrash at 0x7fd0d9b1a758>, 'Initialize': <function Initialize at 0x7fd0d9b1a0c8>, 'output_plugins_status_collection_urn': <property object at 0x7fd0d9b07ba8>, 'StopHuntIfAverageLimitsExceeded': <function StopHuntIfAverageLimitsExceeded at 0x7fd0d9b1c5f0>, '__doc__': u'The GRR Hunt class.', 'LogCollection': <function LogCollection at 0x7fd0d9b1a5f0>, 'SetDescription': <function SetDescription at 0x7fd0d9b1c848>, 'LogCollectionForHID': <classmethod object at 0x7fd0d9b13360>, 'results_collection_urn': <property object at 0x7fd0d9b07a48>, 'GetClientsCounts': <function GetClientsCounts at 0x7fd0d9b1cb90>, 'Name': <function Name at 0x7fd0d9b1c7d0>, 'CreateRunner': <function CreateRunner at 0x7fd0d9b1a1b8>, 'RegisterClient': <function RegisterClient at 0x7fd0d9b1c140>, 'AddResultsToCollection': <function AddResultsToCollection at 0x7fd0d9b1c668>, 'ErrorCollectionForHID': <classmethod object at 0x7fd0d9b13408>, 'clients_with_results_collection_urn': <property object at 0x7fd0d9b07c58>, 'GetClients': <function GetClients at 0x7fd0d9b1cc80>, 'CrashCollectionForHID': <classmethod object at 0x7fd0d9b133d0>, 'output_plugins_base_urn': <property object at 0x7fd0d9b07db8>, '_ValidateState': <function _ValidateState at 0x7fd0d9b1ced8>, 'StartClients': <classmethod object at 0x7fd0d9b13558>, 'MarkClientDone': <function MarkClientDone at 0x7fd0d9b1ca28>, 'CrashCollectionURNForHID': <classmethod object at 0x7fd0d9b13398>, 'completed_clients_collection_urn': <property object at 0x7fd0d9b07d08>, 'output_plugins_errors_collection_urn': <property object at 0x7fd0d9b07c00>, 'RegisterCompletedClient': <function RegisterCompletedClient at 0x7fd0d9b1c1b8>, '_ClientSymlinkUrn': <function _ClientSymlinkUrn at 0x7fd0d9b1c0c8>, 'SchemaCls': <class 'grr_response_server.hunts.implementation.SchemaCls'>, 'AllClientsCollectionForHID': <classmethod object at 0x7fd0d9b134e8>, 'results_metadata_urn': <property object at 0x7fd0d9b07d60>, 'args_type': None, 'GetClientsByStatus': <function GetClientsByStatus at 0x7fd0d9b1cd70>, 'GetClientsErrors': <function GetClientsErrors at 0x7fd0d9b1cc08>, 'MIN_CLIENTS_FOR_AVERAGE_THRESHOLDS': 1000, '_AddURNToCollection': <function _AddURNToCollection at 0x7fd0d9b1af50>, 'CallFlow': <function CallFlow at 0x7fd0d9b1c6e0>, 'PluginErrorCollectionForHID': <classmethod object at 0x7fd0d9b13478>, 'HeartBeat': <function HeartBeat at 0x7fd0d9b1c758>, 'multi_type_output_urn': <property object at 0x7fd0d9b07aa0>}
{'lifetime': <Duration('1d')>, '__module__': 'grr_response_server.flows.cron.data_retention', 'frequency': <Duration('1d')>, '__doc__': u'Cleaner that deletes old hunts.', 'Start': <function Start at 0x7fd0d9b1f1b8>}
{'lifetime': <Duration('1d')>, '__module__': 'grr_response_server.flows.cron.data_retention', 'frequency': <Duration('1d')>, 'Run': <function Run at 0x7fd0d9b1f398>, '__doc__': u'Cleaner that deletes old hunts.'}
{'lifetime': <Duration('1d')>, '__module__': 'grr_response_server.flows.cron.data_retention', 'frequency': <Duration('1d')>, '__doc__': u'Cleaner that deletes old finished cron flows.', 'Start': <function Start at 0x7fd0d9b1f578>}
{'lifetime': <Duration('20h')>, '__module__': 'grr_response_server.flows.cron.data_retention', 'frequency': <Duration('1d')>, 'Run': <function Run at 0x7fd0d9b1f758>, '__doc__': u'Cron job that deletes old cron job data.'}
{'lifetime': <Duration('1d')>, '__module__': 'grr_response_server.flows.cron.data_retention', 'frequency': <Duration('1d')>, '__doc__': u'Cleaner that deletes inactive clients.', 'Start': <function Start at 0x7fd0d9b1fa28>}
{'lifetime': <Duration('20h')>, '__module__': 'grr_response_server.flows.cron.data_retention', 'frequency': <Duration('1d')>, 'Run': <function Run at 0x7fd0d9b1fc08>}
{'__module__': 'grr_response_server.flows.general.discovery', 'protobuf': <class 'grr_response_proto.flows_pb2.InterrogateArgs'>}
{}
{}
{'ProcessMessages': <function ProcessMessages at 0x7fd0d9acbcf8>, '__module__': 'grr_response_server.flows.general.discovery', '__doc__': u'An event handler which will schedule interrogation on client enrollment.', 'EVENTS': [u'ClientEnrollment']}
{'__module__': 'grr_response_server.hunts.standard', 'Run': <function Run at 0x7fd0d9acbe60>, '__doc__': u'A cron job that starts a hunt.'}
{'Start': <function Start at 0x7fd0d9ad30c8>, '__module__': 'grr_response_server.hunts.standard', 'args_type': <class 'grr_response_server.rdfvalues.hunts.CreateGenericHuntFlowArgs'>, '__doc__': u"Create but don't run a GenericHunt with the given name, args and rules.\n\n  As direct write access to the data store is forbidden, we have to use flows to\n  perform any kind of modifications. This flow delegates ACL checks to\n  access control manager.\n  "}
{'Start': <function Start at 0x7fd0d9ad32a8>, '__module__': 'grr_response_server.hunts.standard', 'args_type': <class 'grr_response_server.rdfvalues.hunts.CreateGenericHuntFlowArgs'>, '__doc__': u'Create and run a GenericHunt with the given name, args and rules.\n\n  This flow is different to the CreateGenericHuntFlow in that it\n  immediately runs the hunt it created.\n  '}
{'__module__': 'grr_response_server.hunts.standard', 'protobuf': <class 'grr_response_proto.flows_pb2.SampleHuntArgs'>}
{'__module__': 'grr_response_server.hunts.standard', 'args_type': <class 'grr_response_server.hunts.standard.SampleHuntArgs'>, 'RunClient': <function RunClient at 0x7fd0d9ad3938>, '__doc__': u'This hunt just looks for the presence of a evil.txt in /tmp.\n\n  Scheduling the hunt works like this:\n\n  > hunt = standard.SampleHunt()\n\n  # We want to schedule on clients that run windows and OS_RELEASE 7.\n  > release_rule = rdf_foreman.ForemanAttributeRegex(\n                   field="OS_RELEASE",\n                   attribute_regex="7")\n  > regex_rule = implementation.GRRHunt.MATCH_WINDOWS\n\n  # Run the hunt when both those rules match.\n  > hunt.AddRule([release_rule, regex_rule])\n\n  # Now we can test how many clients in the database match the rules.\n  # Warning, this might take some time since it looks at all the stored clients.\n  > hunt.TestRules()\n\n  Out of 3171 checked clients, 2918 matched the given rule set.\n\n  # This looks good, we exclude the few Linux / Mac clients in the datastore.\n\n  # Now we can start the hunt. Note that this hunt is actually designed for\n  # Linux / Mac clients so the example rules should not be used for this hunt.\n  > hunt.Run()\n\n  ', 'StoreResults': <function StoreResults at 0x7fd0d9ad39b0>}
{'SetDescription': <function SetDescription at 0x7fd0d9ad3c08>, '__module__': 'grr_response_server.hunts.standard', 'RunClient': <function RunClient at 0x7fd0d9ad3cf8>, 'GetLaunchedFlows': <function GetLaunchedFlows at 0x7fd0d9ad3ed8>, 'args_type': <class 'grr_response_server.rdfvalues.hunts.GenericHuntArgs'>, 'Stop': <function Stop at 0x7fd0d9ad3e60>, '_CreateAuditEvent': <function _CreateAuditEvent at 0x7fd0d9ad3b90>, 'started_flows_collection_urn': <property object at 0x7fd0dafe7ba8>, 'MarkDone': <function MarkDone at 0x7fd0d9ad3f50>, 'STOP_BATCH_SIZE': 10000, '_StopLegacy': <function _StopLegacy at 0x7fd0d9ad3d70>, '__doc__': u'This is a hunt to start any flow on multiple clients.', '_StopRelational': <function _StopRelational at 0x7fd0d9ad3de8>}
{'GetFlowArgsClass': <function GetFlowArgsClass at 0x7fd0d9adc1b8>, '__module__': 'grr_response_server.hunts.standard', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client.ClientURN'>, <class 'grr_response_server.rdfvalues.flow_runner.FlowRunnerArgs'>], '__doc__': u'Defines a flow to start on a number of clients.', 'protobuf': <class 'grr_response_proto.flows_pb2.FlowStartRequest'>}
{'__module__': 'grr_response_server.hunts.standard', 'protobuf': <class 'grr_response_proto.flows_pb2.VariableGenericHuntArgs'>, 'rdf_deps': [<class 'grr_response_server.hunts.standard.FlowStartRequest'>, <class 'grr_response_server.rdfvalues.output_plugin.OutputPluginDescriptor'>]}
{'SetDescription': <function SetDescription at 0x7fd0d9ae30c8>, '__module__': 'grr_response_server.hunts.standard', 'RunClient': <function RunClient at 0x7fd0d9ae3140>, 'args_type': <class 'grr_response_server.hunts.standard.VariableGenericHuntArgs'>, 'ManuallyScheduleClients': <function ManuallyScheduleClients at 0x7fd0d9ae31b8>, '__doc__': u'A generic hunt using different flows for each client.'}
{'_GetClientLabelsList': <function _GetClientLabelsList at 0x7fd0d9ae36e0>, '__module__': 'grr_response_server.flows.cron.system', 'Run': <function Run at 0x7fd0d9ae37d0>, 'recency_window': None, 'CLIENT_STATS_URN': <aff4:/stats/ClientFleetStats age=1970-01-01 00:00:00>, 'BeginProcessing': <function BeginProcessing at 0x7fd0d9ae3578>, 'FinishProcessing': <function FinishProcessing at 0x7fd0d9ae3668>, 'ProcessClientFullInfo': <function ProcessClientFullInfo at 0x7fd0d9ae35f0>, '__doc__': u'Base class for all stats processing cron jobs.', '_StatsForLabel': <function _StatsForLabel at 0x7fd0d9ae3758>}
{'__module__': 'grr_response_server.flows.cron.system', 'recency_window': <Duration('30d')>, 'FinishProcessing': <function FinishProcessing at 0x7fd0d9ae3a28>, 'BeginProcessing': <function BeginProcessing at 0x7fd0d9ae39b0>, 'frequency': <Duration('6h')>, 'lifetime': <Duration('6h')>, 'ProcessClientFullInfo': <function ProcessClientFullInfo at 0x7fd0d9ae3aa0>, '__doc__': u'Records relative ratios of GRR versions in 7 day actives.'}
{'__module__': 'grr_response_server.flows.cron.system', 'recency_window': <Duration('30d')>, 'FinishProcessing': <function FinishProcessing at 0x7fd0d9ae3cf8>, 'BeginProcessing': <function BeginProcessing at 0x7fd0d9ae3c80>, 'frequency': <Duration('1d')>, 'lifetime': <Duration('20h')>, 'ProcessClientFullInfo': <function ProcessClientFullInfo at 0x7fd0d9ae3d70>, '__doc__': u'Records relative ratios of OS versions in 7 day actives.'}
{'_bins': [1, 2, 3, 7, 14, 30, 60], '__module__': 'grr_response_server.flows.cron.system', 'recency_window': <Duration('60d')>, 'FinishProcessing': <function FinishProcessing at 0x7fd0d9ae60c8>, '_ValuesForLabel': <function _ValuesForLabel at 0x7fd0d9ae3f50>, 'BeginProcessing': <function BeginProcessing at 0x7fd0d9ae6050>, 'frequency': <Duration('1d')>, 'lifetime': <Duration('20h')>, 'ProcessClientFullInfo': <function ProcessClientFullInfo at 0x7fd0d9ae6140>, '__doc__': u'Calculates a histogram statistics of clients last contacted times.'}
{'_GetClientLabelsList': <function _GetClientLabelsList at 0x7fd0d9ae6500>, '__module__': 'grr_response_server.flows.cron.system', 'recency_window': None, 'CLIENT_STATS_URN': <aff4:/stats/ClientFleetStats age=1970-01-01 00:00:00>, 'BeginProcessing': <function BeginProcessing at 0x7fd0d9ae6320>, 'Start': <function Start at 0x7fd0d9ae65f0>, 'ProcessLegacyClient': <function ProcessLegacyClient at 0x7fd0d9ae6398>, 'FinishProcessing': <function FinishProcessing at 0x7fd0d9ae6488>, 'ProcessClientFullInfo': <function ProcessClientFullInfo at 0x7fd0d9ae6410>, '__doc__': u'A cron job which opens every client in the system.\n\n  We feed all the client objects to the AbstractClientStatsCollector instances.\n  ', '_StatsForLabel': <function _StatsForLabel at 0x7fd0d9ae6578>}
{'__module__': 'grr_response_server.flows.cron.system', 'FinishProcessing': <function FinishProcessing at 0x7fd0d9ae6848>, '_Process': <function _Process at 0x7fd0d9ae68c0>, 'BeginProcessing': <function BeginProcessing at 0x7fd0d9ae67d0>, 'frequency': <Duration('4h')>, 'ProcessLegacyClient': <function ProcessLegacyClient at 0x7fd0d9ae6938>, 'recency_window': <Duration('30d')>, 'ProcessClientFullInfo': <function ProcessClientFullInfo at 0x7fd0d9ae69b0>, '__doc__': u'Records relative ratios of GRR versions in 7 day actives.'}
{'__module__': 'grr_response_server.flows.cron.system', 'FinishProcessing': <function FinishProcessing at 0x7fd0d9ae6c80>, '_Process': <function _Process at 0x7fd0d9ae6cf8>, 'BeginProcessing': <function BeginProcessing at 0x7fd0d9ae6c08>, 'ProcessLegacyClient': <function ProcessLegacyClient at 0x7fd0d9ae6d70>, 'recency_window': <Duration('30d')>, 'ProcessClientFullInfo': <function ProcessClientFullInfo at 0x7fd0d9ae6de8>, '__doc__': u'Records relative ratios of OS versions in 7 day actives.'}
{'_bins': [1, 2, 3, 7, 14, 30, 60], '__module__': 'grr_response_server.flows.cron.system', 'recency_window': <Duration('60d')>, '_ValuesForLabel': <function _ValuesForLabel at 0x7fd0d9aed0c8>, '_Process': <function _Process at 0x7fd0d9aed230>, 'BeginProcessing': <function BeginProcessing at 0x7fd0d9aed140>, 'ProcessLegacyClient': <function ProcessLegacyClient at 0x7fd0d9aed2a8>, 'FinishProcessing': <function FinishProcessing at 0x7fd0d9aed1b8>, 'ProcessClientFullInfo': <function ProcessClientFullInfo at 0x7fd0d9aed320>, '__doc__': u'Calculates a histogram statistics of clients last contacted times.'}
{'lifetime': <Duration('30m')>, '__module__': 'grr_response_server.flows.cron.system', 'frequency': <Duration('1w')>, '__doc__': u'The legacy cron flow which runs an interrogate hunt on all clients.', 'Start': <function Start at 0x7fd0d9aed668>}
{'lifetime': <Duration('30m')>, '__module__': 'grr_response_server.flows.cron.system', 'frequency': <Duration('1w')>, 'Run': <function Run at 0x7fd0d9aed8c0>, '__doc__': u'A cron job which runs an interrogate hunt on all clients.\n\n  Interrogate needs to be run regularly on our clients to keep host information\n  fresh and enable searching by username etc. in the GUI.\n  '}
{'ProcessClients': <function ProcessClients at 0x7fd0d9aedb18>, 'Start': <function Start at 0x7fd0d9aedaa0>, '__module__': 'grr_response_server.flows.cron.system', 'frequency': <Duration('1w')>, '__doc__': u'Deletes outdated client statistics.'}
{'lifetime': <Duration('20h')>, '__module__': 'grr_response_server.flows.cron.system', 'frequency': <Duration('1w')>, 'Run': <function Run at 0x7fd0d9aedcf8>, '__doc__': u'Deletes outdated client statistics.'}
{'lifetime': <Duration('5h')>, '__module__': 'grr_response_server.flows.cron.system', 'frequency': <Duration('6h')>, 'Run': <function Run at 0x7fd0d9aeded8>, '__doc__': u'Cronjob that updates last-ping timestamps for Fleetspeak clients.'}
{'ProcessMessages': <function ProcessMessages at 0x7fd0d9a88320>, '__module__': 'grr_response_server.flows.general.administrative', 'mail_template': <Template memory:7fd0d9a7dcd0>, '__doc__': u'A listener for client crashes.', 'EVENTS': [u'ClientCrash']}
{}
{}
{'category': None, '__module__': 'grr_response_server.flows.general.administrative', 'ProcessMessage': <function ProcessMessage at 0x7fd0d9a889b0>, '__doc__': u'This action pushes client stats to the server automatically.', 'well_known_session_id': <aff4:/flows/S:Stats age=1970-01-01 00:00:00>}
{'__module__': 'grr_response_server.flows.general.administrative', 'protobuf': <class 'grr_response_proto.flows_pb2.DeleteGRRTempFilesArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.paths.PathSpec'>]}
{}
{}
{'__module__': 'grr_response_server.flows.general.administrative', 'protobuf': <class 'grr_response_proto.flows_pb2.UninstallArgs'>}
{}
{}
{}
{}
{'__module__': 'grr_response_server.flows.general.administrative', 'protobuf': <class 'grr_response_proto.flows_pb2.UpdateConfigurationArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.Dict'>]}
{}
{}
{'__module__': 'grr_response_server.flows.general.administrative', 'protobuf': <class 'grr_response_proto.flows_pb2.ExecutePythonHackArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.Dict'>]}
{}
{}
{'__module__': 'grr_response_server.flows.general.administrative', 'protobuf': <class 'grr_response_proto.flows_pb2.ExecuteCommandArgs'>}
{}
{}
{'__module__': 'grr_response_server.flows.general.administrative', 'foreman_cache': None, 'lock': <thread.lock object at 0x7fd0d9b90670>, 'cache_refresh_time': 60, 'ProcessMessage': <function ProcessMessage at 0x7fd0d9ab10c8>, '__doc__': u'The foreman assigns new flows to clients based on their type.\n\n  Clients periodically call the foreman flow to ask for new flows that might be\n  scheduled for them based on their types. This allows the server to schedule\n  flows for entire classes of machines based on certain criteria.\n  ', 'well_known_session_id': <aff4:/flows/F:Foreman age=1970-01-01 00:00:00>}
{'__module__': 'grr_response_server.flows.general.administrative', 'protobuf': <class 'grr_response_proto.flows_pb2.OnlineNotificationArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.standard.DomainEmailAddress'>]}
{}
{}
{'__module__': 'grr_response_server.flows.general.administrative', 'protobuf': <class 'grr_response_proto.flows_pb2.UpdateClientArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFURN'>]}
{}
{}
{'__module__': 'grr_response_server.flows.general.administrative', 'ProcessMessage': <function ProcessMessage at 0x7fd0d9a476e0>, '__doc__': u'A listener for nanny messages.', 'well_known_session_id': <aff4:/flows/F:NannyMessage age=1970-01-01 00:00:00>}
{'__module__': 'grr_response_server.flows.general.administrative', 'ProcessMessage': <function ProcessMessage at 0x7fd0d9a47a28>, 'well_known_session_id': <aff4:/flows/F:ClientAlert age=1970-01-01 00:00:00>}
{'__module__': 'grr_response_server.flows.general.administrative', 'ProcessMessage': <function ProcessMessage at 0x7fd0d9a47cf8>, 'well_known_session_id': <aff4:/flows/F:Startup age=1970-01-01 00:00:00>}
{'__module__': 'grr_response_server.flows.general.administrative', 'protobuf': <class 'grr_response_proto.flows_pb2.KeepAliveArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.Duration'>]}
{}
{}
{'__module__': 'grr_response_server.flows.general.administrative', 'protobuf': <class 'grr_response_proto.flows_pb2.LaunchBinaryArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalue.RDFURN'>]}
{}
{}
{'ProcessMessages': <function ProcessMessages at 0x7fd0d9af7758>, '__module__': 'grr_response_server.flows.general.audit', '_EnsureLogIsIndexedAff4': <function _EnsureLogIsIndexedAff4 at 0x7fd0d9af76e0>, 'EVENTS': [u'Audit'], '_created_logs': set([]), '__doc__': u'Receive the audit events.'}
{'__module__': 'grr_response_server.flows.general.ca_enroller', 'protobuf': <class 'grr_response_proto.flows_pb2.CAEnrolerArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.crypto.Certificate'>]}
{}
{}
{'__module__': 'grr_response_server.flows.general.ca_enroller', 'ProcessMessage': <function ProcessMessage at 0x7fd0d9a4e500>, '__doc__': u'Manage enrolment requests.', 'well_known_session_id': <aff4:/flows/E:Enrol age=1970-01-01 00:00:00>}
{'__module__': 'grr_response_server.check_lib.filters', 'GetFilter': <classmethod object at 0x7fd0d9a00088>, 'ParseObjs': <function ParseObjs at 0x7fd0d99ff1b8>, 'Parse': <function Parse at 0x7fd0d99ff230>, 'filters': {}, 'Validate': <function Validate at 0x7fd0d99ff2a8>, '__doc__': u'A class for looking up filters.\n\n  Filters may be in other libraries or third party code. This class keeps\n  references to each of them so they can be called by name by checks.\n  '}
{'__module__': 'grr_response_server.check_lib.filters', '_GetVal': <function _GetVal at 0x7fd0d99ff500>, 'ParseObjs': <function ParseObjs at 0x7fd0d99ff578>, 'Validate': <function Validate at 0x7fd0d99ff5f0>, '__doc__': u'A filter that extracts target attributes into key/value fields.\n\n  Accepts one or more attributes to collect. Optionally accepts an objectfilter\n  expression to select objects from which attributes are collected.\n  This filter is a convenient way to normalize the names of collected items to\n  use with a generic hint.\n\n  Args:\n    expression: One or more attributes to fetch as comma separated items.\n\n  Yields:\n    AttributedDict RDF values. key is the attribute name, value is the attribute\n    value.\n  ', '_Attrs': <function _Attrs at 0x7fd0d99ff488>}
{'ParseObjs': <function ParseObjs at 0x7fd0d99ff848>, '__module__': 'grr_response_server.check_lib.filters', 'Validate': <function Validate at 0x7fd0d99ff8c0>, '__doc__': u'An objectfilter result processor that accepts runtime parameters.', '_Compile': <function _Compile at 0x7fd0d99ff7d0>}
{'__module__': 'grr_response_server.check_lib.filters', 'Validate': <function Validate at 0x7fd0d99ffaa0>, '__doc__': u'A filter that extracts values from a repeated field.\n\n  This filter is a convenient way to extract repeated items from an object\n  for individual processing.\n\n  Args:\n    objs: One or more objects.\n    expression: An expression specifying what attribute to expand.\n\n  Yields:\n     The RDF values of elements in the repeated fields.\n  ', 'ParseObjs': <function ParseObjs at 0x7fd0d99ffb18>}
{'__module__': 'grr_response_server.check_lib.filters', '__doc__': u'A filter that extracts the first match item from a objectfilter expression.\n\n  Applies an objectfilter expression to an object. The first attribute named in\n  the expression is returned as a key/value item.`\n  This filter is a convenient way to cherry pick selected items from an object\n  for reporting or further filters.\n\n  Args:\n    objs: One or more objects.\n    expression: An objectfilter expression..\n\n  Yields:\n     AttributedDict RDF values for matching items, where key is the attribute\n     name, and value is the attribute value.\n  ', 'ParseObjs': <function ParseObjs at 0x7fd0d99ffcf8>}
{'_TYPES': {u'SOCKET': <function S_ISSOCK at 0x7fd0e3706e60>, u'CHARACTER': <function S_ISCHR at 0x7fd0e3706c08>, u'FIFO': <function S_ISFIFO at 0x7fd0e3706d70>, u'REGULAR': <function S_ISREG at 0x7fd0e3706cf8>, u'SYMLINK': <function S_ISLNK at 0x7fd0e3706de8>, u'DIRECTORY': <function S_ISDIR at 0x7fd0e3706b90>, u'BLOCK': <function S_ISBLK at 0x7fd0e3706c80>}, '_MatchType': <function _MatchType at 0x7fd0d9a08140>, '__module__': 'grr_response_server.check_lib.filters', '_Comparator': <function _Comparator at 0x7fd0d9a08230>, '_Initialize': <function _Initialize at 0x7fd0d9a08398>, '_MatchGid': <function _MatchGid at 0x7fd0d99fff50>, '_Load': <function _Load at 0x7fd0d9a08320>, '_MatchFile': <function _MatchFile at 0x7fd0d99ffed8>, 'ParseObjs': <function ParseObjs at 0x7fd0d9a08410>, '_PERM_RE': <_sre.SRE_Pattern object at 0x7fd0d9a81b30>, '_Flush': <function _Flush at 0x7fd0d9a082a8>, '_KEYS': set([u'uid', u'file_type', u'mask', u'gid', u'mode', u'file_re', u'path_re']), '_MatchPath': <function _MatchPath at 0x7fd0d9a080c8>, '_UID_GID_RE': <_sre.SRE_Pattern object at 0x7fd0d9b76450>, 'Validate': <function Validate at 0x7fd0d9a08488>, '__doc__': u'Filters StatResult RDF Values based on file attributes.\n\n  Filters are added as expressions that include one or more key:value inputs\n  separated by spaced.\n\n  StatResult RDF values can be filtered on several fields:\n  - path_re: A regex search on the pathname attribute.\n  - file_re: A regex search on the filename attribute.\n  - file_type: One of BLOCK,CHARACTER,DIRECTORY,FIFO,REGULAR,SOCKET,SYMLINK\n  - gid: A numeric comparison of gid values: (!|>|>=|<=|<|=)uid\n  - uid: A numeric comparison of uid values: (!|>|>=|<=|<|=)uid\n  - mask: The permissions bits that should be checked. Defaults to 7777.\n  - mode: The permissions bits the StatResult should have after the mask is\n    applied.\n\n  Args:\n    expression: A statfilter expression\n\n  Yields:\n    StatResult objects that match the filter term.\n  ', '_MatchMode': <function _MatchMode at 0x7fd0d9a08050>, '_MatchUid': <function _MatchUid at 0x7fd0d9a081b8>}
{'_GetClass': <function _GetClass at 0x7fd0d9a086e0>, '__module__': 'grr_response_server.check_lib.filters', 'ParseObjs': <function ParseObjs at 0x7fd0d9a08758>, '_RDFTypes': <function _RDFTypes at 0x7fd0d9a08668>, 'Validate': <function Validate at 0x7fd0d9a087d0>, '__doc__': u'Filter results to specified rdf types.'}
{'__module__': 'grr_response_server.check_lib.triggers', '__nonzero__': <function __nonzero__ at 0x7fd0d9a08e60>, 'protobuf': <class 'grr_response_proto.checks_pb2.Target'>, 'Validate': <function Validate at 0x7fd0d9a08ed8>, '__doc__': u'Definitions of hosts to target.', '__init__': <function __init__ at 0x7fd0d9a08de8>}
{'__module__': 'grr_response_server.check_lib.checks', 'protobuf': <class 'grr_response_proto.checks_pb2.Hint'>, 'Render': <function Render at 0x7fd0d9a111b8>, 'Fix': <function Fix at 0x7fd0d9a112a8>, 'Validate': <function Validate at 0x7fd0d9a11320>, 'Problem': <function Problem at 0x7fd0d9a11230>, '__doc__': u'Human-formatted descriptions of problems, fixes and findings.', '__init__': <function __init__ at 0x7fd0d9a11140>}
{'__module__': 'grr_response_server.check_lib.checks', 'rdf_deps': [<class 'grr_response_server.check_lib.checks.Hint'>], 'Parse': <function Parse at 0x7fd0d9a14050>, 'Validate': <function Validate at 0x7fd0d99ff0c8>, '__doc__': u'Generic filter to provide an interface for different types of filter.', '__init__': <function __init__ at 0x7fd0d9a11f50>, 'protobuf': <class 'grr_response_proto.checks_pb2.Filter'>}
{'__module__': 'grr_response_server.check_lib.checks', 'rdf_deps': [<class 'grr_response_server.check_lib.checks.Filter'>, <class 'grr_response_server.check_lib.checks.Hint'>, <class 'grr_response_server.check_lib.triggers.Target'>], 'Parse': <function Parse at 0x7fd0d9a14938>, 'Validate': <function Validate at 0x7fd0d9a149b0>, '__doc__': u'The suite of filters applied to host data.', '__init__': <function __init__ at 0x7fd0d9a148c0>, 'protobuf': <class 'grr_response_proto.checks_pb2.Probe'>}
{'__module__': 'grr_response_server.check_lib.checks', 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.protodict.Dict'>, <class 'grr_response_server.check_lib.checks.Hint'>, <class 'grr_response_server.check_lib.checks.Probe'>, <class 'grr_response_server.check_lib.triggers.Target'>], 'Parse': <function Parse at 0x7fd0d9a21410>, 'Validate': <function Validate at 0x7fd0d9a21488>, '__doc__': u'A specific test method using 0 or more filters to process data.', '__init__': <function __init__ at 0x7fd0d9a21398>, 'protobuf': <class 'grr_response_proto.checks_pb2.Method'>}
{'__module__': 'grr_response_server.check_lib.checks', '__nonzero__': <function __nonzero__ at 0x7fd0d9a2a140>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.anomaly.Anomaly'>], 'ExtendAnomalies': <function ExtendAnomalies at 0x7fd0d9a2a1b8>, '__doc__': u'Results of a single check performed on a host.', 'protobuf': <class 'grr_response_proto.checks_pb2.CheckResult'>}
{'__module__': 'grr_response_server.check_lib.checks', 'rdf_deps': [<class 'grr_response_server.check_lib.checks.CheckResult'>, <class 'grr_response_core.lib.rdfvalues.client.KnowledgeBase'>], '__nonzero__': <function __nonzero__ at 0x7fd0d9a2a848>, '__doc__': u'All results for a single host.', 'protobuf': <class 'grr_response_proto.checks_pb2.CheckResults'>}
{'__module__': 'grr_response_server.check_lib.checks', 'rdf_deps': [<class 'grr_response_server.check_lib.checks.Hint'>, <class 'grr_response_server.check_lib.checks.Method'>, <class 'grr_response_server.check_lib.triggers.Target'>], 'protobuf': <class 'grr_response_proto.checks_pb2.Check'>, 'Parse': <function Parse at 0x7fd0d9a31140>, 'Validate': <function Validate at 0x7fd0d9a311b8>, 'UsesArtifact': <function UsesArtifact at 0x7fd0d9a310c8>, '__doc__': u"A definition of a problem, and ways to detect it.\n\n  Checks contain an identifier of a problem (check_id) that is a reference to an\n  externally or internally defined vulnerability.\n\n  Checks use one or more Methods to determine if an issue exists. Methods define\n  data collection and processing, and return an Anomaly if the conditions tested\n  by the method weren't met.\n\n  Checks can define a default platform, OS or environment to target. This\n  is passed to each Method, but can be overridden by more specific definitions.\n  ", '__init__': <function __init__ at 0x7fd0d9a2af50>, 'SelectChecks': <function SelectChecks at 0x7fd0d9a31050>}
{'__module__': 'grr_response_server.check_lib.checks', 'RunOnce': <function RunOnce at 0x7fd0d9a387d0>, '__doc__': u'Loads checks from the filesystem.'}
{'path_type': <property object at 0x7fd0d9a5b5d0>, '__module__': 'grr_response_server.flows.general.checks', 'protobuf': <class 'grr_response_proto.flows_pb2.CheckFlowArgs'>}
{}
{}
{'category': u'/Administrative/', 'Start': <function Start at 0x7fd0d99e5e60>, '__module__': 'grr_response_server.flows.general.data_migration'}
{'__module__': 'grr_response_server.flows.general.filetypes', 'protobuf': <class 'grr_response_proto.flows_pb2.PlistValueFilterArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.plist.PlistRequest'>]}
{'category': u'/FileTypes/', '__module__': 'grr_response_server.flows.general.filetypes', 'Receive': <function Receive at 0x7fd0d99dcf50>, 'args_type': <class 'grr_response_server.flows.general.filetypes.PlistValueFilterArgs'>, 'Start': <function Start at 0x7fd0d99dced8>, '__doc__': u'Obtains values from a plist based on a context and a query filter.\n\n  This function will parse a plist. Obtain all the values under the path given\n  in context and then filter each of them against the given query and return\n  only these that match. I.e:\n\n  plist = {\n    \'values\': [13, 14, 15]\n    \'items\':\n      [\n        {\'name\': \'John\',\n         \'age\': 33,\n         \'children\': [\'John\', \'Phil\'],\n         },\n        {\'name\': \'Mike\',\n          \'age\': 24,\n          \'children\': [],\n        },\n      ],\n  }\n\n  A call to PlistValueFilter with context "items" and query "age > 25" will\n  return {\'name\': \'John\', \'age\': 33}.\n\n  If you don\'t specify a context, the full plist will be matched and returned\n  if the query succceeds. I,e: a call to PlistValueFilter without a context but\n  query "values contains 13" will return the full plist.\n\n\n  If you don\'t specify a query, all the values under the context parameter will\n  get returned. I.e: a call to PlistValueFilter with context "items.children"\n  and no query, will return [ [\'John\', \'Phil\'], []].\n  '}
{'__module__': 'grr_response_server.flows.general.find', 'Validate': <function Validate at 0x7fd0d99dc6e0>, 'protobuf': <class 'grr_response_proto.flows_pb2.FindFilesArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.client_fs.FindSpec'>]}
{}
{}
{'__module__': 'grr_response_server.flows.general.hardware', 'protobuf': <class 'grr_response_proto.flows_pb2.DumpFlashImageArgs'>}
{}
{}
{'__module__': 'grr_response_server.flows.general.hardware', 'Validate': <function Validate at 0x7fd0d997e1b8>, 'protobuf': <class 'grr_response_proto.flows_pb2.DumpACPITableArgs'>}
{}
{}
{'__module__': 'grr_response_server.flows.general.network', 'protobuf': <class 'grr_response_proto.flows_pb2.NetstatArgs'>}
{}
{}
{}
{}
{'__module__': 'grr_response_server.flows.general.processes', 'protobuf': <class 'grr_response_proto.flows_pb2.ListProcessesArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.standard.RegularExpression'>]}
{}
{}
{'__module__': 'grr_response_server.flows.general.registry', 'protobuf': <class 'grr_response_proto.flows_pb2.RegistryFinderCondition'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderContentsLiteralMatchCondition'>, <class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderContentsRegexMatchCondition'>, <class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderModificationTimeCondition'>, <class 'grr_response_core.lib.rdfvalues.file_finder.FileFinderSizeCondition'>]}
{'__module__': 'grr_response_server.flows.general.registry', 'protobuf': <class 'grr_response_proto.flows_pb2.RegistryFinderArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.paths.GlobExpression'>, <class 'grr_response_server.flows.general.registry.RegistryFinderCondition'>]}
{}
{}
{}
{}
{'Parse': <function Parse at 0x7fd0d99b4aa0>, 'output_types': [u'BrowserHistoryItem'], '__module__': 'grr_response_core.lib.parsers.chrome_history', '__doc__': u'Parse Chrome history files into BrowserHistoryItem objects.', 'supported_artifacts': [u'ChromeHistory']}
{'Parse': <function Parse at 0x7fd0d99b4ed8>, 'output_types': [u'BrowserHistoryItem'], '__module__': 'grr_response_core.lib.parsers.firefox3_history', '__doc__': u'Parse Chrome history files into BrowserHistoryItem objects.', 'supported_artifacts': [u'FirefoxHistory']}
{'__module__': 'grr_response_server.flows.general.webhistory', 'protobuf': <class 'grr_response_proto.flows_pb2.ChromeHistoryArgs'>}
{}
{}
{'__module__': 'grr_response_server.flows.general.webhistory', 'protobuf': <class 'grr_response_proto.flows_pb2.FirefoxHistoryArgs'>}
{}
{}
{'__module__': 'grr_response_server.flows.general.webhistory', 'protobuf': <class 'grr_response_proto.flows_pb2.CacheGrepArgs'>, 'rdf_deps': [<class 'grr_response_core.lib.rdfvalues.standard.RegularExpression'>]}
{}
{}
{'category': u'/Filesystem/', '__module__': 'grr_response_server.flows.general.windows_vsc', 'End': <function End at 0x7fd0d9961398>, 'ProcessListDirectory': <function ProcessListDirectory at 0x7fd0d9961320>, 'ListDeviceDirectories': <function ListDeviceDirectories at 0x7fd0d99612a8>, 'Start': <function Start at 0x7fd0d9961230>, 'behaviours': <grr_response_server.flow.FlowBehaviour object at 0x7fd0d99631d0>, '__doc__': u'List the Volume Shadow Copies on the client.'}
{}
{}
{}
{}

15. A deeper look is needed on artifact_falllback in flows ; 


16. some ui points for further analysis maybe?
  File "/home/samanoudy/.virtualenv/GRR/bin/grr_admin_ui", line 11, in <module>
    load_entry_point('grr-response-server', 'console_scripts', 'grr_admin_ui')()
  File "/home/samanoudy/grr/grr/server/grr_response_server/distro_entry.py", line 49, in AdminUI
    flags.StartMain(admin_ui.main)
  File "/home/samanoudy/grr/grr/core/grr_response_core/lib/flags.py", line 87, in StartMain
    app.run(main)
  File "/home/samanoudy/.virtualenv/GRR/lib/python2.7/site-packages/absl/app.py", line 300, in run
    _run_main(main, args)
  File "/home/samanoudy/.virtualenv/GRR/lib/python2.7/site-packages/absl/app.py", line 251, in _run_main
    sys.exit(main(argv))
  File "/home/samanoudy/grr/grr/server/grr_response_server/gui/admin_ui.py", line 103, in main
    server.serve_forever()
  File "/usr/lib/python2.7/SocketServer.py", line 231, in serve_forever
    poll_interval)
  File "/usr/lib/python2.7/SocketServer.py", line 150, in _eintr_retry
    return func(*args)

17. event logger for nanny written in c++ in grr_response_client/nanny

18. a client can be easily repacked using the client_builder.py tool:
19. example for adding plugins is found in grr_response_client/installer_plugin.py:

python grr/client/grr_response_client/client_build.py \
--config /etc/grr/grr-server.yaml --verbose \
--platform windows --arch amd64 deploy \
-p grr/client/plugins/installer_plugin.py

20. authorization manager exist in response_server/authorization

21.in response_server/aff4_grr: we can find in class VFSGRRClient: fuction update specifies that flow  flow_cls = registry.FlowRegistry.FlowClassByName("Interrogate") which is essentially in discover.py

22. the foreman flow runs depending on rules.. (see more in aff4_grr)

23.     # The client_id is the first element of the URN

24. base classes for flows is in grr_response_server/flows.py: has a runner and response: like FSM

25. look at flowbehavior as well same file

26. difference between startflow() and startaff4flow() ???


____%EOF_______ 


____%BOF%____

1. rseponse_server/gui/in wsgiapp.py, you can manipulate all http connections and methods between server and client.
2. There u can also build access control token for requests...
3. WHat the hell is that???:
static/node_modules/uglify-js/node_modules/yargs/README.md
72:    util.print(argv.fr ? 'Le perroquet dit: ' : 'The parrot says: ');
415:If a `msg` string is given, it will be printed when the argument is missing,
540:Examples will be printed out as part of the help message.
548:A message to print at the end of the usage instructions, e.g.,
568:Method to execute when a failure occurs, rather then printing the failure message.
570:`fn` is called with the failure message that would have been printed.
712:Print the usage data using the [`console`](https://nodejs.org/api/console.html) function `consoleLevel` for printing.
722:Or, to print the usage data to `stdout` instead, you can specify the use of `console.log`:
811:    .example('$0 hello', 'print the hello message!')
819:    .example('$0 world', 'print the world message!')

4. Interrogate button:: directs to discovery.py in InterrogateMixin: start
5. Trying to overwrite the linux.yaml artifact on gui,got:
Traceback (most recent call last):
  File "/home/samanoudy/grr/grr/server/grr_response_server/gui/http_api.py", line 510, in HandleRequest
    result = self.CallApiHandler(handler, args, token=token)
  File "/home/samanoudy/grr/grr/server/grr_response_server/gui/http_api.py", line 298, in CallApiHandler
    result = handler.Handle(args, token=token)
  File "/home/samanoudy/grr/grr/server/grr_response_server/gui/api_plugins/artifact.py", line 92, in Handle
    content, overwrite=True, overwrite_system_artifacts=False)
  File "/home/samanoudy/grr/grr/server/grr_response_server/artifact.py", line 506, in UploadArtifactYamlFile
    overwrite_system_artifacts=overwrite_system_artifacts)
  File "/home/samanoudy/grr/grr/core/grr_response_core/lib/utils.py", line 85, in NewFunction
    return f(self, *args, **kw)
  File "/home/samanoudy/grr/grr/server/grr_response_server/artifact_registry.py", line 310, in RegisterArtifact
    raise rdf_artifacts.ArtifactDefinitionError(artifact_name, details)
ArtifactDefinitionError: AnacronFiles: system artifact cannot be overwritten

6. GetPendingUserNotificationsCount is an API method that is meant
    # to be invoked very often (every 10 seconds). So it's ideal
    # for updating the CSRF (Cross-Site Request Forgery ) token. in wsgiapp:
 See for more details:
  # https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet

7. Look at WSGIHandler at wsgiapp..
8. Note that Werkzeug is The Python WSGI(Web_Server_Gateway_Interface) Utility Library 
9. FirebaseWebAuthManager is the one used for authenticating admin to AdminUi page

10. In http_api: build token; the token and is formed:
message ACLToken {
 expiry : RDFDatetime:
    2019-02-26 16:47:18
 process : u'GRRAdminUI'
 reason : u''
 username : u'admin'
}

11. rdfvalue.RDFDatetime.Now() is late by 2 hours;; why??

12. look in http_api in call_api_handler: these are results:
message ApiClient {
 age : RDFDatetime:
    2019-02-24 15:33:50
 agent_info :   message ClientInformation {
     build_time : u'Unknown'
     client_description : u'GRR linux amd64'
     client_name : u'GRR'
     client_version : 3246
    }
 client_id : ApiClientId:
    C.1be17baa0aeb80b5
 first_seen_at : RDFDatetime:
    2019-02-11 19:16:23
 fleetspeak_enabled : False
 hardware_info :   message HardwareInfo {
    }
 interfaces : [
     message Interface {
      addresses : [
          message NetworkAddress {
           address_type : INET
           packed_bytes : RDFBytes:
              c0a8010c
          }
          message NetworkAddress {
           address_type : INET6
           packed_bytes : RDFBytes:
              fe80000000000000bf81e8413c3d2783
          }
       ]
      ifname : u'wlp2s0'
      mac_address : MacAddress:
         blahblah
     }
     message Interface {
      addresses : [
          message NetworkAddress {
           address_type : INET
           packed_bytes : RDFBytes:
              7f000001
          }
          message NetworkAddress {
           address_type : INET6
           packed_bytes : RDFBytes:
              00000000000000000000000000000001
          }
       ]
      ifname : u'lo'
      mac_address : MacAddress:
         000000000000
     }
     message Interface {
      ifname : u'enp1s0'
      mac_address : MacAddress:
         ecf4bb8bbd60
     }
  ]
 knowledge_base :   message KnowledgeBase {
     fqdn : u'samanoudy-Inspiron-5537'
     os : u'Linux'
     os_major_version : 18
     os_minor_version : 4
     os_release : u'Ubuntu'
     users : [
         message User {
          full_name : u'samanoudy,,,'
          gid : 1000
          homedir : u'/home/samanoudy'
          last_logon : RDFDatetime:
             2019-02-11 17:23:19
          shell : u'/bin/bash'
          uid : 1000
          username : u'samanoudy'
         }
      ]
    }
 labels : [
  ]
 last_booted_at : RDFDatetime:
    2019-02-11 17:20:04
 last_clock : RDFDatetime:
    2019-02-26 16:55:10
 last_crash_at : RDFDatetime:
    2019-02-24 15:33:50
 last_seen_at : RDFDatetime:
    2019-02-26 16:55:10
 memory_size : ByteSize:
    8239411200
 os_info :   message Uname {
     fqdn : u'samanoudy-Inspiron-5537'
     install_date : RDFDatetime:
        2019-01-08 13:39:29
     kernel : u'4.15.0-43-generic'
     machine : u'x86_64'
     release : u'Ubuntu'
     system : u'Linux'
     version : u'18.4'
    }
 urn : ClientURN:
    aff4:/C.1be17baa0aeb80b5
 users : [
     message User {
      full_name : u'samanoudy,,,'
      gid : 1000
      homedir : u'/home/samanoudy'
      last_logon : RDFDatetime:
         2019-02-11 17:23:19
      shell : u'/bin/bash'
      uid : 1000
      username : u'samanoudy'
     }
  ]
 volumes : [
     message Volume {
      actual_available_allocation_units : 19327684
      bytes_per_sector : 4096
      sectors_per_allocation_unit : 1
      total_allocation_units : 25671918
      unixvolume :   message UnixVolume {
          mount_point : u'/'
         }
     }
  ]
}


13. Admin_UI cycle: api call is received in handle_api of wsgiapp which directs the call to http_api; in particular in response = http_api.RenderHttpResponse(request); which redirects to teh HTTPHandler in the same file in response = HTTP_REQUEST_HANDLER.HandleRequest(request); then makes a lot of checks over acls and other stuff preventing some attacks; then it redirects to         result = self.CallApiHandler(handler, args, token=token) which basically redirects the call to the handler object to handle the request; for example: a handler object could be <grr_response_server.gui.api_plugins.user.ApiGetPendingUserNotificationsCountHandler object at 0x7fdabd063490>; there the request is actually handled and the result is given back and Formatted As Json then wrapped using werkzeug_wrappers in _BuildResponse; in the handler object which is mainly located at gui/api_plugins; the actual flow gets started and executed 

14. in func MatchRouter in http_api; you get both request.path, request.method);

15. the routing map is as follows:
Map([<Rule '/api/v2/users/me/notifications/pending/count' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a3d0>>,
 <Rule '/api/users/me/notifications/pending/count' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a3d0>>,
 <Rule '/api/v2/users/me/notifications/pending' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf310>>,
 <Rule '/api/v2/users/me/approvals/cron-job' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aa90>>,
 <Rule '/api/v2/users/me/approvals/client' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a990>>,
 <Rule '/api/v2/users/me/approvals/hunt' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae90>>,
 <Rule '/api/users/me/notifications/pending' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf310>>,
 <Rule '/api/users/me/approvals/cron-job' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aa90>>,
 <Rule '/api/users/me/approvals/client' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a990>>,
 <Rule '/api/users/me/approvals/hunt' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae90>>,
 <Rule '/api/v2/reflection/rdfvalue/all' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf390>>,
 <Rule '/api/v2/reflection/aff4/attributes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a790>>,
 <Rule '/api/v2/clients/labels/remove' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf490>>,
 <Rule '/api/v2/clients/labels/add' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9464d0>>,
 <Rule '/api/v2/users/me/notifications' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a7d0>>,
 <Rule '/api/reflection/rdfvalue/all' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf390>>,
 <Rule '/api/reflection/aff4/attributes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a790>>,
 <Rule '/api/clients/labels/remove' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf490>>,
 <Rule '/api/clients/labels/add' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9464d0>>,
 <Rule '/api/users/me/notifications' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a7d0>>,
 <Rule '/api/v2/output-plugins/all' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf2d0>>,
 <Rule '/api/v2/reflection/file-encodings' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf250>>,
 <Rule '/api/v2/reflection/api-methods' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a810>>,
 <Rule '/api/v2/clients/kb-fields' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf210>>,
 <Rule '/api/v2/clients/labels' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aa10>>,
 <Rule '/api/v2/config/binaries' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae50>>,
 <Rule '/api/v2/users/approver-suggestions' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a890>>,
 <Rule '/api/v2/flows/descriptors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab90>>,
 <Rule '/api/v2/stats/reports' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf3d0>>,
 <Rule '/api/v2/users/me' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a090>>,
 <Rule '/api/v2/users/me' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf510>>,
 <Rule '/api/output-plugins/all' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf2d0>>,
 <Rule '/api/reflection/file-encodings' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf250>>,
 <Rule '/api/reflection/api-methods' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a810>>,
 <Rule '/api/clients/kb-fields' (HEAD, GET) -> <grr_respo <Rule '/api/clients/<client_id>/flows/<flow_id>/output-plugins/<plugin_id>/logs' (HEAD, GET) ->nse_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf210>>,
 <Rule '/api/clients/labels' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aa10>>,
 <Rule '/api/config/binaries' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae50>>,
 <Rule '/api/users/approver-suggestions' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a890>>,
 <Rule '/api/flows/descriptors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab90>>,
 <Rule '/api/stats/reports' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf3d0>>,
 <Rule '/api/users/me' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a090>>,
 <Rule '/api/users/me' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf510>>,
 <Rule '/api/v2/cron-jobs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab10>>,
 <Rule '/api/v2/artifacts' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a8d0>>,
 <Rule '/api/v2/cron-jobs' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9465d0>>,
 <Rule '/api/v2/artifacts' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9467d0>>,
 <Rule '/api/v2/artifacts' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf5d0>>,
 <Rule '/api/v2/clients' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf4d0>>,
 <Rule '/api/v2/config' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a90>>,
 <Rule '/api/v2/hunts' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf1d0>>,
 <Rule '/api/v2/hunts' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9466d0>>,
 <Rule '/api/cron-jobs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab10>>,
 <Rule '/api/artifacts' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a8d0>>,
 <Rule '/api/cron-jobs' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9465d0>>,
 <Rule '/api/artifacts' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9467d0>>,
 <Rule '/api/artifacts' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf5d0>>,
 <Rule '/api/clients' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf4d0>>,
 <Rule '/api/config' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a90>>,
 <Rule '/api/hunts' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf1d0>>,
 <Rule '/api/hunts' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9466d0>>,
 <Rule '/api/v2/users/<username>/approvals/cron-job/<cron_job_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a6d0>>,
 <Rule '/api/v2/users/<username>/approvals/client/<client_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a650>>,
 <Rule '/api/v2/users/<username>/approvals/hunt/<hunt_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a710>>,
 <Rule '/api/users/<username>/approvals/cron-job/<cron_job_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a6d0>>,
 <Rule '/api/users/<username>/approvals/client/<client_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a650>>,
 <Rule '/api/users/<username>/approvals/hunt/<hunt_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a710>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/output-plugins/<plugin_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ac50>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/output-plugins/<plugin_id>/logs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94acd0>>,
 <Rule '/api/v2/hunts/<hunt_id>/results/clients/<client_id>/vfs-blob/<vfs_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a1d0>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/output-plugins/<plugin_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ac50>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/output-plugins/<plugin_id>/logs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94acd0>>,
 <Rule '/api/hunts/<hunt_id>/results/clients/<client_id>/vfs-blob/<vfs_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a1d0>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/exported-results/<plugin_name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946c50>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/results/export-command' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946f90>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/results/files-archive' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946f10>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/actions/cancel' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946510>>,
 <Rule '/api/v2/users/<username>/approvals/cron-job/<cron_job_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b50>>,
 <Rule '/api/v2/users/<username>/approvals/client/<client_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946950>>,
 <Rule '/api/v2/users/<username>/approvals/hunt/<hunt_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a110>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/exported-results/<plugin_name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946c50>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/results/export-command' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946f90>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/results/files-archive' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946f10>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/actions/cancel' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946510>>,
 <Rule '/api/users/<username>/approvals/cron-job/<cron_job_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b50>>,
 <Rule '/api/users/<username>/approvals/client/<client_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946950>>,
 <Rule '/api/users/<username>/approvals/hunt/<hunt_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a110>>,
 <Rule '/api/v2/clients/<client_id>/vfs-decoded-blob/<decoder_name>/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946bd0>>,
 <Rule '/api/v2/clients/<client_id>/actions/interrogate/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a310>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/output-plugins' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ad50>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/requests' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ad90>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/results' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94add0>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/log' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94abd0>>,
 <Rule '/api/v2/users/me/notifications/pending/<timestamp>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946890>>,
 <Rule '/api/v2/users/me/approvals/cron-job/<cron_job_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946650>>,
 <Rule '/api/v2/users/me/approvals/client/<client_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a990>>,
 <Rule '/api/v2/users/me/approvals/client/<client_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946590>>,
 <Rule '/api/v2/users/me/approvals/hunt/<hunt_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946710>>,
 <Rule '/api/v2/hunts/<hunt_id>/output-plugins/<plugin_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf050>>,
 <Rule '/api/v2/hunts/<hunt_id>/output-plugins/<plugin_id>/logs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf0d0>>,
 <Rule '/api/clients/<client_id>/vfs-decoded-blob/<decoder_name>/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946bd0>>,
 <Rule '/api/clients/<client_id>/actions/interrogate/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a310>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/output-plugins' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ad50>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/requests' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ad90>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/results' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94add0>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/log' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94abd0>>,
 <Rule '/api/users/me/notifications/pending/<timestamp>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946890>>,
 <Rule '/api/users/me/approvals/cron-job/<cron_job_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946650>>,
 <Rule '/api/users/me/approvals/client/<client_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a990>>,
 <Rule '/api/users/me/approvals/client/<client_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946590>>,
 <Rule '/api/users/me/approvals/hunt/<hunt_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946710>>,
 <Rule '/api/hunts/<hunt_id>/output-plugins/<plugin_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf050>>,
 <Rule '/api/hunts/<hunt_id>/output-plugins/<plugin_id>/logs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf0d0>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>/actions/force-run' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9468d0>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>/runs/<run_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b90>>,
 <Rule '/api/v2/clients/<client_id>/vfs-refresh-operations/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a590>>,
 <Rule '/api/v2/clients/<client_id>/vfs-download-command/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e10>>,
 <Rule '/api/v2/clients/<client_id>/vfs-version-times/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e90>>,
 <Rule '/api/v2/clients/<client_id>/vfs-files-archive/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a510>>,
 <Rule '/api/v2/clients/<client_id>/vfs-timeline-csv/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a610>>,
 <Rule '/api/v2/clients/<client_id>/vfs-timeline/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a5d0>>,
 <Rule '/api/v2/clients/<client_id>/vfs-decoders/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d50>>,
 <Rule '/api/v2/clients/<client_id>/vfs-details/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d90>>,
 <Rule '/api/v2/clients/<client_id>/load-stats/<metric>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946990>>,
 <Rule '/api/v2/clients/<client_id>/vfs-update/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a4d0>>,
 <Rule '/api/v2/clients/<client_id>/vfs-index/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab50>>,
 <Rule '/api/v2/clients/<client_id>/vfs-text/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e50>>,
 <Rule '/api/v2/clients/<client_id>/vfs-blob/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d10>>,
 <Rule '/api/v2/clients/<client_id>/actions/interrogate' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a750>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946ed0>>,
 <Rule '/api/v2/config/binaries-blobs/<type>/<path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a050>>,
 <Rule '/api/v2/config/binaries/<type>/<path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946fd0>>,
 <Rule '/api/v2/hunts/<hunt_id>/exported-results/<plugin_name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946cd0>>,
 <Rule '/api/v2/hunts/<hunt_id>/results/export-command' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a290>>,
 <Rule '/api/v2/hunts/<hunt_id>/results/files-archive' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a210>>,
 <Rule '/api/v2/hunts/<hunt_id>/clients/<client_status>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aed0>>,
 <Rule '/api/cron-jobs/<cron_job_id>/actions/force-run' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9468d0>>,
 <Rule '/api/cron-jobs/<cron_job_id>/runs/<run_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b90>>,
 <Rule '/api/clients/<client_id>/vfs-refresh-operations/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a590>>,
 <Rule '/api/clients/<client_id>/vfs-download-command/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e10>>,
 <Rule '/api/clients/<client_id>/vfs-version-times/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e90>>,
 <Rule '/api/clients/<client_id>/vfs-files-archive/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a510>>,
 <Rule '/api/clients/<client_id>/vfs-timeline-csv/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a610>>,
 <Rule '/api/clients/<client_id>/vfs-timeline/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a5d0>>,
 <Rule '/api/clients/<client_id>/vfs-decoders/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d50>>,
 <Rule '/api/clients/<client_id>/vfs-details/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d90>>,
 <Rule '/api/clients/<client_id>/load-stats/<metric>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946990>>,
 <Rule '/api/clients/<client_id>/vfs-update/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a4d0>>,
 <Rule '/api/clients/<client_id>/vfs-index/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab50>>,
 <Rule '/api/clients/<client_id>/vfs-text/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e50>>,
 <Rule '/api/clients/<client_id>/vfs-blob/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d10>>,
 <Rule '/api/clients/<client_id>/actions/interrogate' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a750>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946ed0>>,
 <Rule '/api/config/binaries-blobs/<type>/<path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a050>>,
 <Rule '/api/config/binaries/<type>/<path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946fd0>>,
 <Rule '/api/hunts/<hunt_id>/exported-results/<plugin_name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946cd0>>,
 <Rule '/api/hunts/<hunt_id>/results/export-command' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a290>>,
 <Rule '/api/hunts/<hunt_id>/results/files-archive' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a210>>,
 <Rule '/api/hunts/<hunt_id>/clients/<client_status>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aed0>>,
 <Rule '/api/v2/reflection/rdfvalue/<type>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a450>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>/runs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aad0>>,
 <Rule '/api/v2/clients/<client_id>/vfs-refresh-operations' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946790>>,
 <Rule '/api/v2/clients/<client_id>/vfs-files-archive/' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a510>>,
 <Rule '/api/v2/clients/<client_id>/action-requests' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a950>>,
 <Rule '/api/v2/clients/<client_id>/version-times' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a10>>,
 <Rule '/api/v2/clients/<client_id>/vfs-update' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf590>>,
 <Rule '/api/v2/clients/<client_id>/vfs-index/' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab50>>,
 <Rule '/api/v2/clients/<client_id>/versions' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a50>>,
 <Rule '/api/v2/clients/<client_id>/crashes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a9d0>>,
 <Rule '/api/v2/clients/<client_id>/last-ip' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a390>>,
 <Rule '/api/v2/clients/<client_id>/flows' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae10>>,
 <Rule '/api/v2/clients/<client_id>/flows' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946690>>,
 <Rule '/api/v2/stats/reports/<name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a490>>,
 <Rule '/api/v2/hunts/<hunt_id>/client-completion-stats' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a150>>,
 <Rule '/api/v2/hunts/<hunt_id>/output-plugins' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf150>>,
 <Rule '/api/v2/hunts/<hunt_id>/context' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a190>>,
 <Rule '/api/v2/hunts/<hunt_id>/crashes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af10>>,
 <Rule '/api/v2/hunts/<hunt_id>/results' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf190>>,
 <Rule '/api/v2/hunts/<hunt_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af50>>,
 <Rule '/api/v2/hunts/<hunt_id>/stats' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a2d0>>,
 <Rule '/api/v2/hunts/<hunt_id>/log' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af90>>,
 <Rule '/api/reflection/rdfvalue/<type>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a450>>,
 <Rule '/api/cron-jobs/<cron_job_id>/runs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aad0>>,
 <Rule '/api/clients/<client_id>/vfs-refresh-operations' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946790>>,
 <Rule '/api/clients/<client_id>/vfs-files-archive/' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a510>>,
 <Rule '/api/clients/<client_id>/action-requests' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a950>>,
 <Rule '/api/clients/<client_id>/version-times' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a10>>,
 <Rule '/api/clients/<client_id>/vfs-update' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf590>>,
 <Rule '/api/clients/<client_id>/vfs-index/' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab50>>,
 <Rule '/api/clients/<client_id>/versions' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a50>>,
 <Rule '/api/clients/<client_id>/crashes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a9d0>>,
 <Rule '/api/clients/<client_id>/last-ip' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a390>>,
 <Rule '/api/clients/<client_id>/flows' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae10>>,
 <Rule '/api/clients/<client_id>/flows' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946690>>,
 <Rule '/api/stats/reports/<name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a490>>,
 <Rule '/api/hunts/<hunt_id>/client-completion-stats' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a150>>,
 <Rule '/api/hunts/<hunt_id>/output-plugins' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf150>>,
 <Rule '/api/hunts/<hunt_id>/context' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a190>>,
 <Rule '/api/hunts/<hunt_id>/crashes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af10>>,
 <Rule '/api/hunts/<hunt_id>/results' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf190>>,
 <Rule '/api/hunts/<hunt_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af50>>,
 <Rule '/api/hunts/<hunt_id>/stats' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a2d0>>,
 <Rule '/api/hunts/<hunt_id>/log' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af90>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b10>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946810>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>' (PATCH) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf410>>,
 <Rule '/api/v2/clients/<client_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946910>>,
 <Rule '/api/v2/config/<name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946ad0>>,
 <Rule '/api/v2/hunts/<hunt_id>' (PATCH) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf450>>,
 <Rule '/api/v2/hunts/<hunt_id>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946850>>,
 <Rule '/api/v2/hunts/<hunt_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a0d0>>,
 <Rule '/api/cron-jobs/<cron_job_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b10>>,
 <Rule '/api/cron-jobs/<cron_job_id>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946810>>,
 <Rule '/api/cron-jobs/<cron_job_id>' (PATCH) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf410>>,
 <Rule '/api/clients/<client_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946910>>,
 <Rule '/api/config/<name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946ad0>>,
 <Rule '/api/hunts/<hunt_id>' (PATCH) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf450>>,
 <Rule '/api/hunts/<hunt_id>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946850>>,
 <Rule '/api/hunts/<hunt_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a0d0>>])
::ffff:127.0.0.1 - - [01/Mar/2019 10:28:53] "GET /api/clients/C.1be17baa0aeb80b5 HTTP/1.1" 200 4164
Map([<Rule '/api/v2/users/me/notifications/pending/count' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a3d0>>,
 <Rule '/api/users/me/notifications/pending/count' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a3d0>>,
 <Rule '/api/v2/users/me/notifications/pending' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf310>>,
 <Rule '/api/v2/users/me/approvals/cron-job' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aa90>>,
 <Rule '/api/v2/users/me/approvals/client' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a990>>,
 <Rule '/api/v2/users/me/approvals/hunt' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae90>>,
 <Rule '/api/users/me/notifications/pending' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf310>>,
 <Rule '/api/users/me/approvals/cron-job' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aa90>>,
 <Rule '/api/users/me/approvals/client' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a990>>,
 <Rule '/api/users/me/approvals/hunt' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae90>>,
 <Rule '/api/v2/reflection/rdfvalue/all' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf390>>,
 <Rule '/api/v2/reflection/aff4/attributes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a790>>,
 <Rule '/api/v2/clients/labels/remove' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf490>>,
 <Rule '/api/v2/clients/labels/add' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9464d0>>,
 <Rule '/api/v2/users/me/notifications' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a7d0>>,
 <Rule '/api/reflection/rdfvalue/all' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf390>>,
 <Rule '/api/reflection/aff4/attributes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a790>>,
 <Rule '/api/clients/labels/remove' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf490>>,
 <Rule '/api/clients/labels/add' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9464d0>>,
 <Rule '/api/users/me/notifications' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a7d0>>,
 <Rule '/api/v2/output-plugins/all' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf2d0>>,
 <Rule '/api/v2/reflection/file-encodings' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf250>>,
 <Rule '/api/v2/reflection/api-methods' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a810>>,
 <Rule '/api/v2/clients/kb-fields' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf210>>,
 <Rule '/api/v2/clients/labels' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aa10>>,
 <Rule '/api/v2/config/binaries' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae50>>,
 <Rule '/api/v2/users/approver-suggestions' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a890>>,
 <Rule '/api/v2/flows/descriptors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab90>>,
 <Rule '/api/v2/stats/reports' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf3d0>>,
 <Rule '/api/v2/users/me' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a090>>,
 <Rule '/api/v2/users/me' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf510>>,
 <Rule '/api/output-plugins/all' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf2d0>>,
 <Rule '/api/reflection/file-encodings' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf250>>,
 <Rule '/api/reflection/api-methods' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a810>>,
 <Rule '/api/clients/kb-fields' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf210>>,
 <Rule '/api/clients/labels' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aa10>>,
 <Rule '/api/config/binaries' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae50>>,
 <Rule '/api/users/approver-suggestions' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a890>>,
 <Rule '/api/flows/descriptors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab90>>,
 <Rule '/api/stats/reports' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf3d0>>,
 <Rule '/api/users/me' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a090>>,
 <Rule '/api/users/me' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf510>>,
 <Rule '/api/v2/cron-jobs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab10>>,
 <Rule '/api/v2/artifacts' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a8d0>>,
 <Rule '/api/v2/cron-jobs' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9465d0>>,
 <Rule '/api/v2/artifacts' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9467d0>>,
 <Rule '/api/v2/artifacts' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf5d0>>,
 <Rule '/api/v2/clients' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf4d0>>,
 <Rule '/api/v2/config' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a90>>,
 <Rule '/api/v2/hunts' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf1d0>>,
 <Rule '/api/v2/hunts' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9466d0>>,
 <Rule '/api/cron-jobs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab10>>,
 <Rule '/api/artifacts' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a8d0>>,
 <Rule '/api/cron-jobs' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9465d0>>,
 <Rule '/api/artifacts' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9467d0>>,
 <Rule '/api/artifacts' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf5d0>>,
 <Rule '/api/clients' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf4d0>>,
 <Rule '/api/config' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a90>>,
 <Rule '/api/hunts' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf1d0>>,
 <Rule '/api/hunts' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9466d0>>,
 <Rule '/api/v2/users/<username>/approvals/cron-job/<cron_job_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a6d0>>,
 <Rule '/api/v2/users/<username>/approvals/client/<client_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a650>>,
 <Rule '/api/v2/users/<username>/approvals/hunt/<hunt_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a710>>,
 <Rule '/api/users/<username>/approvals/cron-job/<cron_job_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a6d0>>,
 <Rule '/api/users/<username>/approvals/client/<client_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a650>>,
 <Rule '/api/users/<username>/approvals/hunt/<hunt_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a710>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/output-plugins/<plugin_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ac50>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/output-plugins/<plugin_id>/logs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94acd0>>,
 <Rule '/api/v2/hunts/<hunt_id>/results/clients/<client_id>/vfs-blob/<vfs_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a1d0>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/output-plugins/<plugin_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ac50>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/output-plugins/<plugin_id>/logs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94acd0>>,
 <Rule '/api/hunts/<hunt_id>/results/clients/<client_id>/vfs-blob/<vfs_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a1d0>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/exported-results/<plugin_name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946c50>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/results/export-command' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946f90>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/results/files-archive' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946f10>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/actions/cancel' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946510>>,
 <Rule '/api/v2/users/<username>/approvals/cron-job/<cron_job_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b50>>,
 <Rule '/api/v2/users/<username>/approvals/client/<client_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946950>>,
 <Rule '/api/v2/users/<username>/approvals/hunt/<hunt_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a110>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/exported-results/<plugin_name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946c50>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/results/export-command' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946f90>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/results/files-archive' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946f10>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/actions/cancel' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946510>>,
 <Rule '/api/users/<username>/approvals/cron-job/<cron_job_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b50>>,
 <Rule '/api/users/<username>/approvals/client/<client_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946950>>,
 <Rule '/api/users/<username>/approvals/hunt/<hunt_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a110>>,
 <Rule '/api/v2/clients/<client_id>/vfs-decoded-blob/<decoder_name>/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946bd0>>,
 <Rule '/api/v2/clients/<client_id>/actions/interrogate/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a310>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/output-plugins' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ad50>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/requests' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ad90>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/results' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94add0>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/log' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94abd0>>,
 <Rule '/api/v2/users/me/notifications/pending/<timestamp>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946890>>,
 <Rule '/api/v2/users/me/approvals/cron-job/<cron_job_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946650>>,
 <Rule '/api/v2/users/me/approvals/client/<client_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a990>>,
 <Rule '/api/v2/users/me/approvals/client/<client_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946590>>,
 <Rule '/api/v2/users/me/approvals/hunt/<hunt_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946710>>,
 <Rule '/api/v2/hunts/<hunt_id>/output-plugins/<plugin_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf050>>,
 <Rule '/api/v2/hunts/<hunt_id>/output-plugins/<plugin_id>/logs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf0d0>>,
 <Rule '/api/clients/<client_id>/vfs-decoded-blob/<decoder_name>/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946bd0>>,
 <Rule '/api/clients/<client_id>/actions/interrogate/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a310>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/output-plugins' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ad50>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/requests' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ad90>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/results' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94add0>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/log' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94abd0>>,
 <Rule '/api/users/me/notifications/pending/<timestamp>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946890>>,
 <Rule '/api/users/me/approvals/cron-job/<cron_job_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946650>>,
 <Rule '/api/users/me/approvals/client/<client_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a990>>,
 <Rule '/api/users/me/approvals/client/<client_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946590>>,
 <Rule '/api/users/me/approvals/hunt/<hunt_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946710>>,
 <Rule '/api/hunts/<hunt_id>/output-plugins/<plugin_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf050>>,
 <Rule '/api/hunts/<hunt_id>/output-plugins/<plugin_id>/logs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf0d0>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>/actions/force-run' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9468d0>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>/runs/<run_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b90>>,
 <Rule '/api/v2/clients/<client_id>/vfs-refresh-operations/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a590>>,
 <Rule '/api/v2/clients/<client_id>/vfs-download-command/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e10>>,
 <Rule '/api/v2/clients/<client_id>/vfs-version-times/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e90>>,
 <Rule '/api/v2/clients/<client_id>/vfs-files-archive/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a510>>,
 <Rule '/api/v2/clients/<client_id>/vfs-timeline-csv/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a610>>,
 <Rule '/api/v2/clients/<client_id>/vfs-timeline/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a5d0>>,
 <Rule '/api/v2/clients/<client_id>/vfs-decoders/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d50>>,
 <Rule '/api/v2/clients/<client_id>/vfs-details/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d90>>,
 <Rule '/api/v2/clients/<client_id>/load-stats/<metric>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946990>>,
 <Rule '/api/v2/clients/<client_id>/vfs-update/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a4d0>>,
 <Rule '/api/v2/clients/<client_id>/vfs-index/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab50>>,
 <Rule '/api/v2/clients/<client_id>/vfs-text/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e50>>,
 <Rule '/api/v2/clients/<client_id>/vfs-blob/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d10>>,
 <Rule '/api/v2/clients/<client_id>/actions/interrogate' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a750>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946ed0>>,
 <Rule '/api/v2/config/binaries-blobs/<type>/<path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a050>>,
 <Rule '/api/v2/config/binaries/<type>/<path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946fd0>>,
 <Rule '/api/v2/hunts/<hunt_id>/exported-results/<plugin_name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946cd0>>,
 <Rule '/api/v2/hunts/<hunt_id>/results/export-command' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a290>>,
 <Rule '/api/v2/hunts/<hunt_id>/results/files-archive' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a210>>,
 <Rule '/api/v2/hunts/<hunt_id>/clients/<client_status>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aed0>>,
 <Rule '/api/cron-jobs/<cron_job_id>/actions/force-run' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9468d0>>,
 <Rule '/api/cron-jobs/<cron_job_id>/runs/<run_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b90>>,
 <Rule '/api/clients/<client_id>/vfs-refresh-operations/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a590>>,
 <Rule '/api/clients/<client_id>/vfs-download-command/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e10>>,
 <Rule '/api/clients/<client_id>/vfs-version-times/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e90>>,
 <Rule '/api/clients/<client_id>/vfs-files-archive/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a510>>,
 <Rule '/api/clients/<client_id>/vfs-timeline-csv/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a610>>,
 <Rule '/api/clients/<client_id>/vfs-timeline/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a5d0>>,
 <Rule '/api/clients/<client_id>/vfs-decoders/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d50>>,
 <Rule '/api/clients/<client_id>/vfs-details/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d90>>,
 <Rule '/api/clients/<client_id>/load-stats/<metric>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946990>>,
 <Rule '/api/clients/<client_id>/vfs-update/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a4d0>>,
 <Rule '/api/clients/<client_id>/vfs-index/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab50>>,
 <Rule '/api/clients/<client_id>/vfs-text/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e50>>,
 <Rule '/api/clients/<client_id>/vfs-blob/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d10>>,
 <Rule '/api/clients/<client_id>/actions/interrogate' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a750>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946ed0>>,
 <Rule '/api/config/binaries-blobs/<type>/<path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a050>>,
 <Rule '/api/config/binaries/<type>/<path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946fd0>>,
 <Rule '/api/hunts/<hunt_id>/exported-results/<plugin_name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946cd0>>,
 <Rule '/api/hunts/<hunt_id>/results/export-command' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a290>>,
 <Rule '/api/hunts/<hunt_id>/results/files-archive' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a210>>,
 <Rule '/api/hunts/<hunt_id>/clients/<client_status>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aed0>>,
 <Rule '/api/v2/reflection/rdfvalue/<type>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a450>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>/runs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aad0>>,
 <Rule '/api/v2/clients/<client_id>/vfs-refresh-operations' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946790>>,
 <Rule '/api/v2/clients/<client_id>/vfs-files-archive/' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a510>>,
 <Rule '/api/v2/clients/<client_id>/action-requests' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a950>>,
 <Rule '/api/v2/clients/<client_id>/version-times' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a10>>,
 <Rule '/api/v2/clients/<client_id>/vfs-update' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf590>>,
 <Rule '/api/v2/clients/<client_id>/vfs-index/' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab50>>,
 <Rule '/api/v2/clients/<client_id>/versions' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a50>>,
 <Rule '/api/v2/clients/<client_id>/crashes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a9d0>>,
 <Rule '/api/v2/clients/<client_id>/last-ip' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a390>>,
 <Rule '/api/v2/clients/<client_id>/flows' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae10>>,
 <Rule '/api/v2/clients/<client_id>/flows' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946690>>,
 <Rule '/api/v2/stats/reports/<name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a490>>,
 <Rule '/api/v2/hunts/<hunt_id>/client-completion-stats' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a150>>,
 <Rule '/api/v2/hunts/<hunt_id>/output-plugins' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf150>>,
 <Rule '/api/v2/hunts/<hunt_id>/context' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a190>>,
 <Rule '/api/v2/hunts/<hunt_id>/crashes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af10>>,
 <Rule '/api/v2/hunts/<hunt_id>/results' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf190>>,
 <Rule '/api/v2/hunts/<hunt_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af50>>,
 <Rule '/api/v2/hunts/<hunt_id>/stats' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a2d0>>,
 <Rule '/api/v2/hunts/<hunt_id>/log' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af90>>,
 <Rule '/api/reflection/rdfvalue/<type>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a450>>,
 <Rule '/api/cron-jobs/<cron_job_id>/runs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aad0>>,
 <Rule '/api/clients/<client_id>/vfs-refresh-operations' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946790>>,
 <Rule '/api/clients/<client_id>/vfs-files-archive/' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a510>>,
 <Rule '/api/clients/<client_id>/action-requests' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a950>>,
 <Rule '/api/clients/<client_id>/version-times' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a10>>,
 <Rule '/api/clients/<client_id>/vfs-update' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf590>>,
 <Rule '/api/clients/<client_id>/vfs-index/' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab50>>,
 <Rule '/api/clients/<client_id>/versions' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a50>>,
 <Rule '/api/clients/<client_id>/crashes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a9d0>>,
 <Rule '/api/clients/<client_id>/last-ip' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a390>>,
 <Rule '/api/clients/<client_id>/flows' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae10>>,
 <Rule '/api/clients/<client_id>/flows' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946690>>,
 <Rule '/api/stats/reports/<name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a490>>,
 <Rule '/api/hunts/<hunt_id>/client-completion-stats' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a150>>,
 <Rule '/api/hunts/<hunt_id>/output-plugins' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf150>>,
 <Rule '/api/hunts/<hunt_id>/context' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a190>>,
 <Rule '/api/hunts/<hunt_id>/crashes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af10>>,
 <Rule '/api/hunts/<hunt_id>/results' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf190>>,
 <Rule '/api/hunts/<hunt_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af50>>,
 <Rule '/api/hunts/<hunt_id>/stats' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a2d0>>,
 <Rule '/api/hunts/<hunt_id>/log' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af90>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b10>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946810>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>' (PATCH) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf410>>,
 <Rule '/api/v2/clients/<client_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946910>>,
 <Rule '/api/v2/config/<name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946ad0>>,
 <Rule '/api/v2/hunts/<hunt_id>' (PATCH) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf450>>,
 <Rule '/api/v2/hunts/<hunt_id>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946850>>,
 <Rule '/api/v2/hunts/<hunt_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a0d0>>,
 <Rule '/api/cron-jobs/<cron_job_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b10>>,
 <Rule '/api/cron-jobs/<cron_job_id>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946810>>,
 <Rule '/api/cron-jobs/<cron_job_id>' (PATCH) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf410>>,
 <Rule '/api/clients/<client_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946910>>,
 <Rule '/api/config/<name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946ad0>>,
 <Rule '/api/hunts/<hunt_id>' (PATCH) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf450>>,
 <Rule '/api/hunts/<hunt_id>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946850>>,
 <Rule '/api/hunts/<hunt_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a0d0>>])Map([<Rule '/api/v2/users/me/notifications/pending/count' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a3d0>>,
 <Rule '/api/users/me/notifications/pending/count' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a3d0>>,
 <Rule '/api/v2/users/me/notifications/pending' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf310>>,
 <Rule '/api/v2/users/me/approvals/cron-job' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aa90>>,
 <Rule '/api/v2/users/me/approvals/client' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a990>>,
 <Rule '/api/v2/users/me/approvals/hunt' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae90>>,
 <Rule '/api/users/me/notifications/pending' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf310>>,
 <Rule '/api/users/me/approvals/cron-job' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aa90>>,
 <Rule '/api/users/me/approvals/client' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a990>>,
 <Rule '/api/users/me/approvals/hunt' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae90>>,
 <Rule '/api/v2/reflection/rdfvalue/all' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf390>>,
 <Rule '/api/v2/reflection/aff4/attributes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a790>>,
 <Rule '/api/v2/clients/labels/remove' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf490>>,
 <Rule '/api/v2/clients/labels/add' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9464d0>>,
 <Rule '/api/v2/users/me/notifications' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a7d0>>,
 <Rule '/api/reflection/rdfvalue/all' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf390>>,
 <Rule '/api/reflection/aff4/attributes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a790>>,
 <Rule '/api/clients/labels/remove' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf490>>,
 <Rule '/api/clients/labels/add' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9464d0>>,
 <Rule '/api/users/me/notifications' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a7d0>>,
 <Rule '/api/v2/output-plugins/all' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf2d0>>,
 <Rule '/api/v2/reflection/file-encodings' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf250>>,
 <Rule '/api/v2/reflection/api-methods' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a810>>,
 <Rule '/api/v2/clients/kb-fields' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf210>>,
 <Rule '/api/v2/clients/labels' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aa10>>,
 <Rule '/api/v2/config/binaries' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae50>>,
 <Rule '/api/v2/users/approver-suggestions' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a890>>,
 <Rule '/api/v2/flows/descriptors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab90>>,
 <Rule '/api/v2/stats/reports' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf3d0>>,
 <Rule '/api/v2/users/me' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a090>>,
 <Rule '/api/v2/users/me' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf510>>,
 <Rule '/api/output-plugins/all' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf2d0>>,
 <Rule '/api/reflection/file-encodings' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf250>>,
 <Rule '/api/reflection/api-methods' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a810>>,
 <Rule '/api/clients/kb-fields' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf210>>,
 <Rule '/api/clients/labels' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aa10>>,
 <Rule '/api/config/binaries' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae50>>,
 <Rule '/api/users/approver-suggestions' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a890>>,
 <Rule '/api/flows/descriptors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab90>>,
 <Rule '/api/stats/reports' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf3d0>>,
 <Rule '/api/users/me' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a090>>,
 <Rule '/api/users/me' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf510>>,
 <Rule '/api/v2/cron-jobs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab10>>,
 <Rule '/api/v2/artifacts' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a8d0>>,
 <Rule '/api/v2/cron-jobs' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9465d0>>,
 <Rule '/api/v2/artifacts' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9467d0>>,
 <Rule '/api/v2/artifacts' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf5d0>>,
 <Rule '/api/v2/clients' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf4d0>>,
 <Rule '/api/v2/config' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a90>>,
 <Rule '/api/v2/hunts' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf1d0>>,
 <Rule '/api/v2/hunts' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9466d0>>,
 <Rule '/api/cron-jobs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab10>>,
 <Rule '/api/artifacts' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a8d0>>,
 <Rule '/api/cron-jobs' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9465d0>>,
 <Rule '/api/artifacts' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9467d0>>,
 <Rule '/api/artifacts' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf5d0>>,
 <Rule '/api/clients' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf4d0>>,
 <Rule '/api/config' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a90>>,
 <Rule '/api/hunts' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf1d0>>,
 <Rule '/api/hunts' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9466d0>>,
 <Rule '/api/v2/users/<username>/approvals/cron-job/<cron_job_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a6d0>>,
 <Rule '/api/v2/users/<username>/approvals/client/<client_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a650>>,
 <Rule '/api/v2/users/<username>/approvals/hunt/<hunt_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a710>>,
 <Rule '/api/users/<username>/approvals/cron-job/<cron_job_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a6d0>>,
 <Rule '/api/users/<username>/approvals/client/<client_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a650>>,
 <Rule '/api/users/<username>/approvals/hunt/<hunt_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a710>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/output-plugins/<plugin_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ac50>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/output-plugins/<plugin_id>/logs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94acd0>>,
 <Rule '/api/v2/hunts/<hunt_id>/results/clients/<client_id>/vfs-blob/<vfs_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a1d0>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/output-plugins/<plugin_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ac50>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/output-plugins/<plugin_id>/logs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94acd0>>,
 <Rule '/api/hunts/<hunt_id>/results/clients/<client_id>/vfs-blob/<vfs_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a1d0>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/exported-results/<plugin_name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946c50>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/results/export-command' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946f90>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/results/files-archive' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946f10>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/actions/cancel' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946510>>,
 <Rule '/api/v2/users/<username>/approvals/cron-job/<cron_job_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b50>>,
 <Rule '/api/v2/users/<username>/approvals/client/<client_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946950>>,
 <Rule '/api/v2/users/<username>/approvals/hunt/<hunt_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a110>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/exported-results/<plugin_name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946c50>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/results/export-command' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946f90>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/results/files-archive' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946f10>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/actions/cancel' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946510>>,
 <Rule '/api/users/<username>/approvals/cron-job/<cron_job_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b50>>,
 <Rule '/api/users/<username>/approvals/client/<client_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946950>>,
 <Rule '/api/users/<username>/approvals/hunt/<hunt_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a110>>,
 <Rule '/api/v2/clients/<client_id>/vfs-decoded-blob/<decoder_name>/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946bd0>>,
 <Rule '/api/v2/clients/<client_id>/actions/interrogate/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a310>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/output-plugins' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ad50>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/requests' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ad90>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/results' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94add0>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/log' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94abd0>>,
 <Rule '/api/v2/users/me/notifications/pending/<timestamp>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946890>>,
 <Rule '/api/v2/users/me/approvals/cron-job/<cron_job_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946650>>,
 <Rule '/api/v2/users/me/approvals/client/<client_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a990>>,
 <Rule '/api/v2/users/me/approvals/client/<client_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946590>>,
 <Rule '/api/v2/users/me/approvals/hunt/<hunt_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946710>>,
 <Rule '/api/v2/hunts/<hunt_id>/output-plugins/<plugin_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf050>>,
 <Rule '/api/v2/hunts/<hunt_id>/output-plugins/<plugin_id>/logs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf0d0>>,
 <Rule '/api/clients/<client_id>/vfs-decoded-blob/<decoder_name>/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946bd0>>,
 <Rule '/api/clients/<client_id>/actions/interrogate/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a310>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/output-plugins' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ad50>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/requests' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ad90>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/results' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94add0>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/log' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94abd0>>,
 <Rule '/api/users/me/notifications/pending/<timestamp>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946890>>,
 <Rule '/api/users/me/approvals/cron-job/<cron_job_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946650>>,
 <Rule '/api/users/me/approvals/client/<client_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a990>>,
 <Rule '/api/users/me/approvals/client/<client_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946590>>,
 <Rule '/api/users/me/approvals/hunt/<hunt_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946710>>,
 <Rule '/api/hunts/<hunt_id>/output-plugins/<plugin_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf050>>,
 <Rule '/api/hunts/<hunt_id>/output-plugins/<plugin_id>/logs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf0d0>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>/actions/force-run' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9468d0>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>/runs/<run_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b90>>,
 <Rule '/api/v2/clients/<client_id>/vfs-refresh-operations/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a590>>,
 <Rule '/api/v2/clients/<client_id>/vfs-download-command/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e10>>,
 <Rule '/api/v2/clients/<client_id>/vfs-version-times/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e90>>,
 <Rule '/api/v2/clients/<client_id>/vfs-files-archive/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a510>>,
 <Rule '/api/v2/clients/<client_id>/vfs-timeline-csv/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a610>>,
 <Rule '/api/v2/clients/<client_id>/vfs-timeline/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a5d0>>,
 <Rule '/api/v2/clients/<client_id>/vfs-decoders/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d50>>,
 <Rule '/api/v2/clients/<client_id>/vfs-details/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d90>>,
 <Rule '/api/v2/clients/<client_id>/load-stats/<metric>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946990>>,
 <Rule '/api/v2/clients/<client_id>/vfs-update/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a4d0>>,
 <Rule '/api/v2/clients/<client_id>/vfs-index/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab50>>,
 <Rule '/api/v2/clients/<client_id>/vfs-text/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e50>>,
 <Rule '/api/v2/clients/<client_id>/vfs-blob/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d10>>,
 <Rule '/api/v2/clients/<client_id>/actions/interrogate' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a750>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946ed0>>,
 <Rule '/api/v2/config/binaries-blobs/<type>/<path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a050>>,
 <Rule '/api/v2/config/binaries/<type>/<path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946fd0>>,
 <Rule '/api/v2/hunts/<hunt_id>/exported-results/<plugin_name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946cd0>>,
 <Rule '/api/v2/hunts/<hunt_id>/results/export-command' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a290>>,
 <Rule '/api/v2/hunts/<hunt_id>/results/files-archive' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a210>>,
 <Rule '/api/v2/hunts/<hunt_id>/clients/<client_status>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aed0>>,
 <Rule '/api/cron-jobs/<cron_job_id>/actions/force-run' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9468d0>>,
 <Rule '/api/cron-jobs/<cron_job_id>/runs/<run_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b90>>,
 <Rule '/api/clients/<client_id>/vfs-refresh-operations/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a590>>,
 <Rule '/api/clients/<client_id>/vfs-download-command/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e10>>,
 <Rule '/api/clients/<client_id>/vfs-version-times/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e90>>,
 <Rule '/api/clients/<client_id>/vfs-files-archive/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a510>>,
 <Rule '/api/clients/<client_id>/vfs-timeline-csv/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a610>>,
 <Rule '/api/clients/<client_id>/vfs-timeline/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a5d0>>,
 <Rule '/api/clients/<client_id>/vfs-decoders/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d50>>,
 <Rule '/api/clients/<client_id>/vfs-details/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d90>>,
 <Rule '/api/clients/<client_id>/load-stats/<metric>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946990>>,
 <Rule '/api/clients/<client_id>/vfs-update/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a4d0>>,
 <Rule '/api/clients/<client_id>/vfs-index/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab50>>,
 <Rule '/api/clients/<client_id>/vfs-text/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e50>>,
 <Rule '/api/clients/<client_id>/vfs-blob/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d10>>,
 <Rule '/api/clients/<client_id>/actions/interrogate' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a750>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946ed0>>,
 <Rule '/api/config/binaries-blobs/<type>/<path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a050>>,
 <Rule '/api/config/binaries/<type>/<path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946fd0>>,
 <Rule '/api/hunts/<hunt_id>/exported-results/<plugin_name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946cd0>>,
 <Rule '/api/hunts/<hunt_id>/results/export-command' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a290>>,
 <Rule '/api/hunts/<hunt_id>/results/files-archive' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a210>>,
 <Rule '/api/hunts/<hunt_id>/clients/<client_status>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aed0>>,
 <Rule '/api/v2/reflection/rdfvalue/<type>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a450>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>/runs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aad0>>,
 <Rule '/api/v2/clients/<client_id>/vfs-refresh-operations' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946790>>,
 <Rule '/api/v2/clients/<client_id>/vfs-files-archive/' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a510>>,
 <Rule '/api/v2/clients/<client_id>/action-requests' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a950>>,
 <Rule '/api/v2/clients/<client_id>/version-times' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a10>>,
 <Rule '/api/v2/clients/<client_id>/vfs-update' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf590>>,
 <Rule '/api/v2/clients/<client_id>/vfs-index/' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab50>>,
 <Rule '/api/v2/clients/<client_id>/versions' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a50>>,
 <Rule '/api/v2/clients/<client_id>/crashes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a9d0>>,
 <Rule '/api/v2/clients/<client_id>/last-ip' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a390>>,
 <Rule '/api/v2/clients/<client_id>/flows' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae10>>,
 <Rule '/api/v2/clients/<client_id>/flows' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946690>>,
 <Rule '/api/v2/stats/reports/<name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a490>>,
 <Rule '/api/v2/hunts/<hunt_id>/client-completion-stats' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a150>>,
 <Rule '/api/v2/hunts/<hunt_id>/output-plugins' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf150>>,
 <Rule '/api/v2/hunts/<hunt_id>/context' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a190>>,
 <Rule '/api/v2/hunts/<hunt_id>/crashes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af10>>,
 <Rule '/api/v2/hunts/<hunt_id>/results' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf190>>,
 <Rule '/api/v2/hunts/<hunt_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af50>>,
 <Rule '/api/v2/hunts/<hunt_id>/stats' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a2d0>>,
 <Rule '/api/v2/hunts/<hunt_id>/log' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af90>>,
 <Rule '/api/reflection/rdfvalue/<type>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a450>>,
 <Rule '/api/cron-jobs/<cron_job_id>/runs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aad0>>,
 <Rule '/api/clients/<client_id>/vfs-refresh-operations' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946790>>,
 <Rule '/api/clients/<client_id>/vfs-files-archive/' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a510>>,
 <Rule '/api/clients/<client_id>/action-requests' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a950>>,
 <Rule '/api/clients/<client_id>/version-times' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a10>>,
 <Rule '/api/clients/<client_id>/vfs-update' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf590>>,
 <Rule '/api/clients/<client_id>/vfs-index/' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab50>>,
 <Rule '/api/clients/<client_id>/versions' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a50>>,
 <Rule '/api/clients/<client_id>/crashes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a9d0>>,
 <Rule '/api/clients/<client_id>/last-ip' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a390>>,
 <Rule '/api/clients/<client_id>/flows' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae10>>,
 <Rule '/api/clients/<client_id>/flows' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946690>>,
 <Rule '/api/stats/reports/<name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a490>>,
 <Rule '/api/hunts/<hunt_id>/client-completion-stats' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a150>>,
 <Rule '/api/hunts/<hunt_id>/output-plugins' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf150>>,
 <Rule '/api/hunts/<hunt_id>/context' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a190>>,
 <Rule '/api/hunts/<hunt_id>/crashes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af10>>,
 <Rule '/api/hunts/<hunt_id>/results' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf190>>,
 <Rule '/api/hunts/<hunt_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af50>>,
 <Rule '/api/hunts/<hunt_id>/stats' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a2d0>>,
 <Rule '/api/hunts/<hunt_id>/log' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af90>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b10>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946810>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>' (PATCH) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf410>>,
 <Rule '/api/v2/clients/<client_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946910>>,
 <Rule '/api/v2/config/<name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946ad0>>,
 <Rule '/api/v2/hunts/<hunt_id>' (PATCH) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf450>>,
 <Rule '/api/v2/hunts/<hunt_id>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946850>>,
 <Rule '/api/v2/hunts/<hunt_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a0d0>>,
 <Rule '/api/cron-jobs/<cron_job_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b10>>,
 <Rule '/api/cron-jobs/<cron_job_id>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946810>>,
 <Rule '/api/cron-jobs/<cron_job_id>' (PATCH) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf410>>,
 <Rule '/api/clients/<client_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946910>>,
 <Rule '/api/config/<name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946ad0>>,
 <Rule '/api/hunts/<hunt_id>' (PATCH) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf450>>,
 <Rule '/api/hunts/<hunt_id>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946850>>,
 <Rule '/api/hunts/<hunt_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a0d0>>])

Map([<Rule '/api/v2/users/me/notifications/pending/count' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a3d0>>,
 <Rule '/api/users/me/notifications/pending/count' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a3d0>>,
 <Rule '/api/v2/users/me/notifications/pending' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf310>>,
 <Rule '/api/v2/users/me/approvals/cron-job' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aa90>>,
 <Rule '/api/v2/users/me/approvals/client' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a990>>,
 <Rule '/api/v2/users/me/approvals/hunt' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae90>>,
 <Rule '/api/users/me/notifications/pending' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf310>>,
 <Rule '/api/users/me/approvals/cron-job' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aa90>>,
 <Rule '/api/users/me/approvals/client' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a990>>,
 <Rule '/api/users/me/approvals/hunt' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae90>>,
 <Rule '/api/v2/reflection/rdfvalue/all' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf390>>,
 <Rule '/api/v2/reflection/aff4/attributes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a790>>,
 <Rule '/api/v2/clients/labels/remove' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf490>>,
 <Rule '/api/v2/clients/labels/add' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9464d0>>,
 <Rule '/api/v2/users/me/notifications' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a7d0>>,
 <Rule '/api/reflection/rdfvalue/all' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf390>>,
 <Rule '/api/reflection/aff4/attributes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a790>>,
 <Rule '/api/clients/labels/remove' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf490>>,
 <Rule '/api/clients/labels/add' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9464d0>>,
 <Rule '/api/users/me/notifications' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a7d0>>,
 <Rule '/api/v2/output-plugins/all' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf2d0>>,
 <Rule '/api/v2/reflection/file-encodings' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf250>>,
 <Rule '/api/v2/reflection/api-methods' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a810>>,
 <Rule '/api/v2/clients/kb-fields' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf210>>,
 <Rule '/api/v2/clients/labels' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aa10>>,
 <Rule '/api/v2/config/binaries' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae50>>,
 <Rule '/api/v2/users/approver-suggestions' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a890>>,
 <Rule '/api/v2/flows/descriptors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab90>>,
 <Rule '/api/v2/stats/reports' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf3d0>>,
 <Rule '/api/v2/users/me' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a090>>,
 <Rule '/api/v2/users/me' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf510>>,
 <Rule '/api/output-plugins/all' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf2d0>>,
 <Rule '/api/reflection/file-encodings' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf250>>,
 <Rule '/api/reflection/api-methods' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a810>>,
 <Rule '/api/clients/kb-fields' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf210>>,
 <Rule '/api/clients/labels' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aa10>>,
 <Rule '/api/config/binaries' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae50>>,
 <Rule '/api/users/approver-suggestions' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a890>>,
 <Rule '/api/flows/descriptors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab90>>,
 <Rule '/api/stats/reports' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf3d0>>,
 <Rule '/api/users/me' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a090>>,
 <Rule '/api/users/me' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf510>>,
 <Rule '/api/v2/cron-jobs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab10>>,
 <Rule '/api/v2/artifacts' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a8d0>>,
 <Rule '/api/v2/cron-jobs' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9465d0>>,
 <Rule '/api/v2/artifacts' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9467d0>>,
 <Rule '/api/v2/artifacts' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf5d0>>,
 <Rule '/api/v2/clients' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf4d0>>,
 <Rule '/api/v2/config' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a90>>,
 <Rule '/api/v2/hunts' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf1d0>>,
 <Rule '/api/v2/hunts' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9466d0>>,
 <Rule '/api/cron-jobs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab10>>,
 <Rule '/api/artifacts' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a8d0>>,
 <Rule '/api/cron-jobs' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9465d0>>,
 <Rule '/api/artifacts' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9467d0>>,
 <Rule '/api/artifacts' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf5d0>>,
 <Rule '/api/clients' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf4d0>>,
 <Rule '/api/config' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a90>>,
 <Rule '/api/hunts' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf1d0>>,
 <Rule '/api/hunts' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9466d0>>,
 <Rule '/api/v2/users/<username>/approvals/cron-job/<cron_job_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a6d0>>,
 <Rule '/api/v2/users/<username>/approvals/client/<client_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a650>>,
 <Rule '/api/v2/users/<username>/approvals/hunt/<hunt_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a710>>,
 <Rule '/api/users/<username>/approvals/cron-job/<cron_job_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a6d0>>,
 <Rule '/api/users/<username>/approvals/client/<client_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a650>>,
 <Rule '/api/users/<username>/approvals/hunt/<hunt_id>/<approval_id>/actions/grant' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a710>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/output-plugins/<plugin_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ac50>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/output-plugins/<plugin_id>/logs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94acd0>>,
 <Rule '/api/v2/hunts/<hunt_id>/results/clients/<client_id>/vfs-blob/<vfs_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a1d0>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/output-plugins/<plugin_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ac50>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/output-plugins/<plugin_id>/logs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94acd0>>,
 <Rule '/api/hunts/<hunt_id>/results/clients/<client_id>/vfs-blob/<vfs_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a1d0>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/exported-results/<plugin_name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946c50>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/results/export-command' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946f90>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/results/files-archive' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946f10>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/actions/cancel' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946510>>,
 <Rule '/api/v2/users/<username>/approvals/cron-job/<cron_job_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b50>>,
 <Rule '/api/v2/users/<username>/approvals/client/<client_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946950>>,
 <Rule '/api/v2/users/<username>/approvals/hunt/<hunt_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a110>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/exported-results/<plugin_name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946c50>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/results/export-command' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946f90>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/results/files-archive' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946f10>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/actions/cancel' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946510>>,
 <Rule '/api/users/<username>/approvals/cron-job/<cron_job_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b50>>,
 <Rule '/api/users/<username>/approvals/client/<client_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946950>>,
 <Rule '/api/users/<username>/approvals/hunt/<hunt_id>/<approval_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a110>>,
 <Rule '/api/v2/clients/<client_id>/vfs-decoded-blob/<decoder_name>/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946bd0>>,
 <Rule '/api/v2/clients/<client_id>/actions/interrogate/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a310>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/output-plugins' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ad50>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/requests' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ad90>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/results' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94add0>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>/log' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94abd0>>,
 <Rule '/api/v2/users/me/notifications/pending/<timestamp>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946890>>,
 <Rule '/api/v2/users/me/approvals/cron-job/<cron_job_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946650>>,
 <Rule '/api/v2/users/me/approvals/client/<client_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a990>>,
 <Rule '/api/v2/users/me/approvals/client/<client_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946590>>,
 <Rule '/api/v2/users/me/approvals/hunt/<hunt_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946710>>,
 <Rule '/api/v2/hunts/<hunt_id>/output-plugins/<plugin_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf050>>,
 <Rule '/api/v2/hunts/<hunt_id>/output-plugins/<plugin_id>/logs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf0d0>>,
 <Rule '/api/clients/<client_id>/vfs-decoded-blob/<decoder_name>/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946bd0>>,
 <Rule '/api/clients/<client_id>/actions/interrogate/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a310>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/output-plugins' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ad50>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/requests' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ad90>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/results' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94add0>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>/log' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94abd0>>,
 <Rule '/api/users/me/notifications/pending/<timestamp>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946890>>,
 <Rule '/api/users/me/approvals/cron-job/<cron_job_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946650>>,
 <Rule '/api/users/me/approvals/client/<client_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a990>>,
 <Rule '/api/users/me/approvals/client/<client_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946590>>,
 <Rule '/api/users/me/approvals/hunt/<hunt_id>' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946710>>,
 <Rule '/api/hunts/<hunt_id>/output-plugins/<plugin_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf050>>,
 <Rule '/api/hunts/<hunt_id>/output-plugins/<plugin_id>/logs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf0d0>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>/actions/force-run' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9468d0>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>/runs/<run_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b90>>,
 <Rule '/api/v2/clients/<client_id>/vfs-refresh-operations/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a590>>,
 <Rule '/api/v2/clients/<client_id>/vfs-download-command/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e10>>,
 <Rule '/api/v2/clients/<client_id>/vfs-version-times/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e90>>,
 <Rule '/api/v2/clients/<client_id>/vfs-files-archive/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a510>>,
 <Rule '/api/v2/clients/<client_id>/vfs-timeline-csv/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a610>>,
 <Rule '/api/v2/clients/<client_id>/vfs-timeline/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a5d0>>,
 <Rule '/api/v2/clients/<client_id>/vfs-decoders/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d50>>,
 <Rule '/api/v2/clients/<client_id>/vfs-details/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d90>>,
 <Rule '/api/v2/clients/<client_id>/load-stats/<metric>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946990>>,
 <Rule '/api/v2/clients/<client_id>/vfs-update/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a4d0>>,
 <Rule '/api/v2/clients/<client_id>/vfs-index/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab50>>,
 <Rule '/api/v2/clients/<client_id>/vfs-text/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e50>>,
 <Rule '/api/v2/clients/<client_id>/vfs-blob/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d10>>,
 <Rule '/api/v2/clients/<client_id>/actions/interrogate' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a750>>,
 <Rule '/api/v2/clients/<client_id>/flows/<flow_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946ed0>>,
 <Rule '/api/v2/config/binaries-blobs/<type>/<path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a050>>,
 <Rule '/api/v2/config/binaries/<type>/<path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946fd0>>,
 <Rule '/api/v2/hunts/<hunt_id>/exported-results/<plugin_name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946cd0>>,
 <Rule '/api/v2/hunts/<hunt_id>/results/export-command' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a290>>,
 <Rule '/api/v2/hunts/<hunt_id>/results/files-archive' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a210>>,
 <Rule '/api/v2/hunts/<hunt_id>/clients/<client_status>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aed0>>,
 <Rule '/api/cron-jobs/<cron_job_id>/actions/force-run' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d9468d0>>,
 <Rule '/api/cron-jobs/<cron_job_id>/runs/<run_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b90>>,
 <Rule '/api/clients/<client_id>/vfs-refresh-operations/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a590>>,
 <Rule '/api/clients/<client_id>/vfs-download-command/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e10>>,
 <Rule '/api/clients/<client_id>/vfs-version-times/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e90>>,
 <Rule '/api/clients/<client_id>/vfs-files-archive/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a510>>,
 <Rule '/api/clients/<client_id>/vfs-timeline-csv/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a610>>,
 <Rule '/api/clients/<client_id>/vfs-timeline/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a5d0>>,
 <Rule '/api/clients/<client_id>/vfs-decoders/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d50>>,
 <Rule '/api/clients/<client_id>/vfs-details/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d90>>,
 <Rule '/api/clients/<client_id>/load-stats/<metric>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946990>>,
 <Rule '/api/clients/<client_id>/vfs-update/<operation_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a4d0>>,
 <Rule '/api/clients/<client_id>/vfs-index/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab50>>,
 <Rule '/api/clients/<client_id>/vfs-text/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946e50>>,
 <Rule '/api/clients/<client_id>/vfs-blob/<file_path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946d10>>,
 <Rule '/api/clients/<client_id>/actions/interrogate' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a750>>,
 <Rule '/api/clients/<client_id>/flows/<flow_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946ed0>>,
 <Rule '/api/config/binaries-blobs/<type>/<path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a050>>,
 <Rule '/api/config/binaries/<type>/<path>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946fd0>>,
 <Rule '/api/hunts/<hunt_id>/exported-results/<plugin_name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946cd0>>,
 <Rule '/api/hunts/<hunt_id>/results/export-command' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a290>>,
 <Rule '/api/hunts/<hunt_id>/results/files-archive' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a210>>,
 <Rule '/api/hunts/<hunt_id>/clients/<client_status>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aed0>>,
 <Rule '/api/v2/reflection/rdfvalue/<type>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a450>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>/runs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aad0>>,
 <Rule '/api/v2/clients/<client_id>/vfs-refresh-operations' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946790>>,
 <Rule '/api/v2/clients/<client_id>/vfs-files-archive/' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a510>>,
 <Rule '/api/v2/clients/<client_id>/action-requests' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a950>>,
 <Rule '/api/v2/clients/<client_id>/version-times' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a10>>,
 <Rule '/api/v2/clients/<client_id>/vfs-update' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf590>>,
 <Rule '/api/v2/clients/<client_id>/vfs-index/' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab50>>,
 <Rule '/api/v2/clients/<client_id>/versions' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a50>>,
 <Rule '/api/v2/clients/<client_id>/crashes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a9d0>>,
 <Rule '/api/v2/clients/<client_id>/last-ip' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a390>>,
 <Rule '/api/v2/clients/<client_id>/flows' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae10>>,
 <Rule '/api/v2/clients/<client_id>/flows' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946690>>,
 <Rule '/api/v2/stats/reports/<name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a490>>,
 <Rule '/api/v2/hunts/<hunt_id>/client-completion-stats' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a150>>,
 <Rule '/api/v2/hunts/<hunt_id>/output-plugins' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf150>>,
 <Rule '/api/v2/hunts/<hunt_id>/context' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a190>>,
 <Rule '/api/v2/hunts/<hunt_id>/crashes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af10>>,
 <Rule '/api/v2/hunts/<hunt_id>/results' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf190>>,
 <Rule '/api/v2/hunts/<hunt_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af50>>,
 <Rule '/api/v2/hunts/<hunt_id>/stats' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a2d0>>,
 <Rule '/api/v2/hunts/<hunt_id>/log' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af90>>,
 <Rule '/api/reflection/rdfvalue/<type>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a450>>,
 <Rule '/api/cron-jobs/<cron_job_id>/runs' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94aad0>>,
 <Rule '/api/clients/<client_id>/vfs-refresh-operations' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946790>>,
 <Rule '/api/clients/<client_id>/vfs-files-archive/' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a510>>,
 <Rule '/api/clients/<client_id>/action-requests' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a950>>,
 <Rule '/api/clients/<client_id>/version-times' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a10>>,
 <Rule '/api/clients/<client_id>/vfs-update' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf590>>,
 <Rule '/api/clients/<client_id>/vfs-index/' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ab50>>,
 <Rule '/api/clients/<client_id>/versions' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946a50>>,
 <Rule '/api/clients/<client_id>/crashes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a9d0>>,
 <Rule '/api/clients/<client_id>/last-ip' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a390>>,
 <Rule '/api/clients/<client_id>/flows' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94ae10>>,
 <Rule '/api/clients/<client_id>/flows' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946690>>,
 <Rule '/api/stats/reports/<name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a490>>,
 <Rule '/api/hunts/<hunt_id>/client-completion-stats' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a150>>,
 <Rule '/api/hunts/<hunt_id>/output-plugins' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf150>>,
 <Rule '/api/hunts/<hunt_id>/context' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a190>>,
 <Rule '/api/hunts/<hunt_id>/crashes' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af10>>,
 <Rule '/api/hunts/<hunt_id>/results' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf190>>,
 <Rule '/api/hunts/<hunt_id>/errors' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af50>>,
 <Rule '/api/hunts/<hunt_id>/stats' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a2d0>>,
 <Rule '/api/hunts/<hunt_id>/log' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94af90>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b10>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946810>>,
 <Rule '/api/v2/cron-jobs/<cron_job_id>' (PATCH) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf410>>,
 <Rule '/api/v2/clients/<client_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946910>>,
 <Rule '/api/v2/config/<name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946ad0>>,
 <Rule '/api/v2/hunts/<hunt_id>' (PATCH) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf450>>,
 <Rule '/api/v2/hunts/<hunt_id>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946850>>,
 <Rule '/api/v2/hunts/<hunt_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a0d0>>,
 <Rule '/api/cron-jobs/<cron_job_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946b10>>,
 <Rule '/api/cron-jobs/<cron_job_id>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946810>>,
 <Rule '/api/cron-jobs/<cron_job_id>' (PATCH) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf410>>,
 <Rule '/api/clients/<client_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946910>>,
 <Rule '/api/config/<name>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946ad0>>,
 <Rule '/api/hunts/<hunt_id>' (PATCH) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2c8cf450>>,
 <Rule '/api/hunts/<hunt_id>' (DELETE) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946850>>,
 <Rule '/api/hunts/<hunt_id>' (HEAD, GET) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d94a0d0>>])


16. OUTPUT_PLUGINS: in api_call_router:
 @Category("Flows")
  @ArgsType(api_flow.ApiGetExportedFlowResultsArgs)
  @ResultBinaryStream()
  @Http("GET", "/api/clients/<client_id>/flows/<path:flow_id>/"
        "exported-results/<plugin_name>")
  def GetExportedFlowResults(self, args, token=None):
    """Stream flow results using one of the instant output plugins."""

    raise NotImplementedError()

17. Sample of the args sent in request:
message ApiGetClientArgs {
 client_id : ApiClientId:
    C.1be17baa0aeb80b5
}
::ffff:127.0.0.1 - - [01/Mar/2019 11:14:08] "GET /api/clients/C.1be17baa0aeb80b5 HTTP/1.1" 200 4164
message ApiGetLastClientIPAddressArgs {
 client_id : ApiClientId:
    C.1be17baa0aeb80b5
}
 message ApiListClientApprovalsArgs {
 client_id : ApiClientId:
    C.1be17baa0aeb80b5
}
::ffff:127.0.0.1 - - [01/Mar/2019 11:14:08] "GET /api/clients/C.1be17baa0aeb80b5/last-ip HTTP/1.1" 200 78

18. # HEAD method is only used for checking the ACLs for particular API
      # methods.

19. handler gets the object name out of the router object and metadata method assoicated with it and attaches the args with it;
so the importance lies in the handler objects to deal with thereafter

20. <grr_response_server.gui.api_plugins.client.ApiInterrogateClientHandler object at 0x7f0c802108d0>
for interrogate;

21. """API handlers for accessing and searching clients and managing labels."""
in response_server/gui/api_plugins/client


23. entry to execute python code:
ERROR:2019-03-01 12:05:20,285 7934 MainProcess 139745113081600 Thread-3 http_api:576] Error while processing /api/clients/C.1be17baa0aeb80b5/flows (POST) with ApiCreateFlowHandler: Executable binary None not found.
Traceback (most recent call last):
  File "/home/samanoudy/grr/grr/server/grr_response_server/gui/http_api.py", line 527, in HandleRequest
    result = self.CallApiHandler(handler, args, token=token)
  File "/home/samanoudy/grr/grr/server/grr_response_server/gui/http_api.py", line 303, in CallApiHandler
    result = handler.Handle(args, token=token)
  File "/home/samanoudy/grr/grr/server/grr_response_server/gui/api_plugins/flow.py", line 1315, in Handle
    runner_args=runner_args)
  File "/home/samanoudy/grr/grr/server/grr_response_server/flow.py", line 308, in StartAFF4Flow
    flow_obj.Start()
  File "/home/samanoudy/grr/grr/server/grr_response_server/flows/general/administrative.py", line 960, in Start
    raise flow.FlowError("Executable binary %s not found." % self.args.binary)
FlowError: Executable binary None not found.

24. uploading a pyton hack result:
R) samanoudy@samanoudy-Inspiron-5537:~/grr/grr$ grr_config_updater upload_python --file=custom.py --platform=linux
Using configuration <GrrConfigManager  file="/home/samanoudy/grr/grr/core/install_data/etc/grr-server.yaml"  file="/home/samanoudy/grr/grr/core/install_data/etc/server.local.yaml" >
Uploaded to aff4:/config/python_hacks/linux/custom.py


25. got the following error; no clue why:
ERROR:2019-03-02 00:39:27,202 9179 MainProcess 139676136490752 Thread-206 wsgiapp:332] http exception: /third-party/jstree/themes/default/32px.png [GET]
Traceback (most recent call last):
  File "/home/samanoudy/grr/grr/server/grr_response_server/gui/wsgiapp.py", line 329, in __call__
    endpoint, _ = matcher.match(request.path, request.method)
  File "/home/samanoudy/.virtualenv/GRR/lib/python2.7/site-packages/werkzeug/routing.py", line 1563, in match
    raise NotFound()
NotFound: 404: Not Found
::ffff:127.0.0.1 - - [02/Mar/2019 00:39:27] "GET /static/third-party/jstree/themes/default/32px.png HTTP/1.1" 404 233


26. Lauch binary exampele of args:
message ApiCreateFlowArgs {
 client_id : ApiClientId:
    C.1be17baa0aeb80b5
 flow :   message ApiFlow {
     args :   <LaunchBinaryArgs('message LaunchBinaryArgs {\n binary : RDFURN:\n    aff4:/config/python_hacks/linux/custom.py\n}')>
     runner_args :   message FlowRunnerArgs {
         output_plugins : [
          ]
        }
    }
 original_flow :   message ApiFlowReference {
    }
}


The runner args:
message FlowRunnerArgs {
 flow_name : u'LaunchBinary'
 output_plugins : [
  ]
}

27. ApiCreateFlowHandler in api_pugins/flow:
it redirects to response_server/flow in startaff4flow:   """The main factory function for creating and executing a new flow.

28. Remember we want to take in the args: name of flows to be determined as a one flow and created thereafter;
also; take the code as text from gui not as uploaded file

29. Args received in res_server/flows is
 message LaunchBinaryArgs {
 binary : RDFURN:
    aff4:/config/python_hacks/linux/custom.py
}

30. <class 'abc.LaunchBinary'> is the one found in registery when searching for flow name in registery
	
31. <class 'grr_response_server.flows.general.administrative.LaunchBinaryArgs'> is the type of args sent in LaunchBinary Message

32. when starting a flow, make sure  whether data_store.RelationalDBFlowsEnabled():
and never forget to create flow runner runner = flow_obj.CreateRunner(;
and make sure u start either synchronously or asynchronusly by setting a certain flag;
and then get appropriate flow urn which u can use in sth like the following: [[USE THE ABSTRACTION OF AFF4 FOR NOWWW]
fd = aff4.FACTORY.Open(flow_id, aff4_type=flow.GRRFlow, token=token)
return ApiFlow().InitFromAff4Object(fd, flow_id=flow_id.Basename())

33. simple runner has the following: <class 'grr_response_server.flows.general.administrative.LaunchBinaryArgs'>
<grr_response_server.flow_runner.FlowRunner object at 0x7fbaa8521a50>

34. leave it to the runner to create the appropriate flow urn for the flow: for example:
aff4:/C.1be17baa0aeb80b5/flows/F:E8FE09D2

35. this is where launchbinary lies in the map:
 <Rule '/api/clients/<client_id>/flows' (POST) -> <grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f3b2d946690>>,

36. here is the router: 
<grr_response_server.gui.api_call_router_without_checks.ApiCallRouterWithoutChecks object at 0x7efc51391dd0>

37. here is the matcher: ( router_method_metadata, route_args_dict )
(<grr_response_server.gui.api_call_router.RouterMethodMetadata object at 0x7f61504be850>, {'client_id': u'C.1be17baa0aeb80b5'})

38. here is the request path:
/api/clients/C.1be17baa0aeb80b5

39. we use what was in 37 alongside request itself to create the request args; we end up having sth like thaT:
message ApiCreateFlowArgs {
 client_id : ApiClientId:
    C.1be17baa0aeb80b5
 flow :   message ApiFlow {
     args :   <LaunchBinaryArgs('message LaunchBinaryArgs {\n binary : RDFURN:\n    aff4:/config/python_hacks/linux/custom.py\n}')>
     runner_args :   message FlowRunnerArgs {
         flow_name : u'LaunchBinary'
         output_plugins : [
          ]
        }
    }
}

40. request is like this:
<HttpRequest 'http://localhost:8000/api/clients/C.1be17baa0aeb80b5/flows' [POST]>

41. creation of args happen here:   def _GetArgsFromRequest(self, request, method_metadata, route_args):

42. The rdf struct for args has the following fields:
<TypeDescriptorSet for TypeDescriptorSet>
 client_id: Client id.
 flow: 
 original_flow: 
</TypeDescriptorSet>

43. There is a fuckin #MYSTERY in here:
    payload = json.loads(request.get_data(as_text=True) or "{}")::
	{u'flow': {u'args': {u'binary': u'aff4:/config/python_hacks/linux/custom.py'}, u'runner_args': {u'flow_name': u'LaunchBinary', u'output_plugins': []}}}

but request:
<HttpRequest 'http://localhost:8000/api/clients/C.1be17baa0aeb80b5/flows' [POST]>


44. #EXAMPLE::: router method metadata:
name:CreateFlow
doc:Start a new flow on a given client.
args_type: <class 'grr_response_server.gui.api_plugins.flow.ApiCreateFlowArgs'> 
result_type:<class 'grr_response_server.gui.api_plugins.flow.ApiFlow'>
category: Flows
http_methods: [(u'POST', u'/api/clients/<client_id>/flows', {'strip_root_types': False})]
no_audit_log_required: False

45. all available http_methods:
[(u'POST', u'/api/clients/labels/add', {'strip_root_types': True})]
[(u'POST', u'/api/clients/<client_id>/flows/<path:flow_id>/actions/cancel', {'strip_root_types': True})]
[(u'POST', u'/api/users/me/approvals/client/<client_id>', {'strip_root_types': False})]
[(u'POST', u'/api/cron-jobs', {'strip_root_types': False})]
[(u'POST', u'/api/users/me/approvals/cron-job/<cron_job_id>', {'strip_root_types': False})]
[(u'POST', u'/api/clients/<client_id>/flows', {'strip_root_types': False})]
[(u'POST', u'/api/hunts', {'strip_root_types': False})]
[(u'POST', u'/api/users/me/approvals/hunt/<hunt_id>', {'strip_root_types': False})]
[(u'POST', u'/api/clients/<client_id>/vfs-refresh-operations', {'strip_root_types': True})]
[(u'DELETE', u'/api/artifacts', {'strip_root_types': True})]
[(u'DELETE', u'/api/cron-jobs/<cron_job_id>', {'strip_root_types': True})]
[(u'DELETE', u'/api/hunts/<hunt_id>', {'strip_root_types': False})]
[(u'DELETE', u'/api/users/me/notifications/pending/<timestamp>', {'strip_root_types': True})]
[(u'POST', u'/api/cron-jobs/<cron_job_id>/actions/force-run', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>', {'strip_root_types': False})]
[(u'GET', u'/api/users/<username>/approvals/client/<client_id>/<approval_id>', {'strip_root_types': False})]
[(u'GET', u'/api/clients/<client_id>/load-stats/<metric>', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/version-times', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/versions', {'strip_root_types': True})]
[(u'GET', u'/api/config', {'strip_root_types': True})]
[(u'GET', u'/api/config/<name>', {'strip_root_types': True})]
[(u'GET', u'/api/cron-jobs/<cron_job_id>', {'strip_root_types': False})]
[(u'GET', u'/api/users/<username>/approvals/cron-job/<cron_job_id>/<approval_id>', {'strip_root_types': False})]
[(u'GET', u'/api/cron-jobs/<cron_job_id>/runs/<run_id>', {'strip_root_types': False})]
[(u'GET', u'/api/clients/<client_id>/vfs-decoded-blob/<decoder_name>/<path:file_path>', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/flows/<path:flow_id>/exported-results/<plugin_name>', {'strip_root_types': True})]
[(u'GET', u'/api/hunts/<hunt_id>/exported-results/<plugin_name>', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/vfs-blob/<path:file_path>', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/vfs-decoders/<path:file_path>', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/vfs-details/<path:file_path>', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/vfs-download-command/<path:file_path>', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/vfs-text/<path:file_path>', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/vfs-version-times/<path:file_path>', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/flows/<path:flow_id>', {'strip_root_types': False})]
[(u'GET', u'/api/clients/<client_id>/flows/<path:flow_id>/results/files-archive', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/flows/<path:flow_id>/results/export-command', {'strip_root_types': True})]
[(u'GET', u'/api/config/binaries/<type>/<path:path>', {'strip_root_types': True})]
[(u'GET', u'/api/config/binaries-blobs/<type>/<path:path>', {'strip_root_types': True})]
[(u'GET', u'/api/users/me', {'strip_root_types': False})]
[(u'GET', u'/api/hunts/<hunt_id>', {'strip_root_types': False})]
[(u'GET', u'/api/users/<username>/approvals/hunt/<hunt_id>/<approval_id>', {'strip_root_types': False})]
[(u'GET', u'/api/hunts/<hunt_id>/client-completion-stats', {'strip_root_types': True})]
[(u'GET', u'/api/hunts/<hunt_id>/context', {'strip_root_types': True})]
[(u'GET', u'/api/hunts/<hunt_id>/results/clients/<client_id>/vfs-blob/<path:vfs_path>', {'strip_root_types': True})]
[(u'GET', u'/api/hunts/<hunt_id>/results/files-archive', {'strip_root_types': True})]
[(u'GET', u'/api/hunts/<hunt_id>/results/export-command', {'strip_root_types': True})]
[(u'GET', u'/api/hunts/<hunt_id>/stats', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/actions/interrogate/<path:operation_id>', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/last-ip', {'strip_root_types': True})]
[(u'GET', u'/api/users/me/notifications/pending/count', {'strip_root_types': True})]
[(u'GET', u'/api/reflection/rdfvalue/<type>', {'strip_root_types': False})]
[(u'GET', u'/api/stats/reports/<name>', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/vfs-update/<path:operation_id>', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/vfs-files-archive/<path:file_path>', {'strip_root_types': True}), (u'GET', u'/api/clients/<client_id>/vfs-files-archive/', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/vfs-refresh-operations/<path:operation_id>', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/vfs-timeline/<path:file_path>', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/vfs-timeline-csv/<path:file_path>', {'strip_root_types': True})]
[(u'POST', u'/api/users/<username>/approvals/client/<client_id>/<approval_id>/actions/grant', {'strip_root_types': False})]
[(u'POST', u'/api/users/<username>/approvals/cron-job/<cron_job_id>/<approval_id>/actions/grant', {'strip_root_types': False})]
[(u'POST', u'/api/users/<username>/approvals/hunt/<hunt_id>/<approval_id>/actions/grant', {'strip_root_types': False})]
[(u'POST', u'/api/clients/<client_id>/actions/interrogate', {'strip_root_types': True})]
[(u'GET', u'/api/reflection/aff4/attributes', {'strip_root_types': True})]
[(u'POST', u'/api/users/me/notifications', {'strip_root_types': True})]
[(u'GET', u'/api/reflection/api-methods', {'strip_root_types': True})]
[(u'GET', u'/api/users/approver-suggestions', {'strip_root_types': True})]
[(u'GET', u'/api/artifacts', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/action-requests', {'strip_root_types': True})]
[(u'GET', u'/api/users/me/approvals/client/<client_id>', {'strip_root_types': True}), (u'GET', u'/api/users/me/approvals/client', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/crashes', {'strip_root_types': True})]
[(u'GET', u'/api/clients/labels', {'strip_root_types': True})]
[(u'GET', u'/api/users/me/approvals/cron-job', {'strip_root_types': True})]
[(u'GET', u'/api/cron-jobs/<cron_job_id>/runs', {'strip_root_types': True})]
[(u'GET', u'/api/cron-jobs', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/vfs-index/<path:file_path>', {'strip_root_types': True}), (u'GET', u'/api/clients/<client_id>/vfs-index/', {'strip_root_types': True})]
[(u'GET', u'/api/flows/descriptors', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/flows/<path:flow_id>/log', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/flows/<path:flow_id>/output-plugins/<plugin_id>/errors', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/flows/<path:flow_id>/output-plugins/<plugin_id>/logs', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/flows/<path:flow_id>/output-plugins', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/flows/<path:flow_id>/requests', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/flows/<path:flow_id>/results', {'strip_root_types': True})]
[(u'GET', u'/api/clients/<client_id>/flows', {'strip_root_types': True})]
[(u'GET', u'/api/config/binaries', {'strip_root_types': True})]
[(u'GET', u'/api/users/me/approvals/hunt', {'strip_root_types': True})]
[(u'GET', u'/api/hunts/<hunt_id>/clients/<client_status>', {'strip_root_types': True})]
[(u'GET', u'/api/hunts/<hunt_id>/crashes', {'strip_root_types': True})]
[(u'GET', u'/api/hunts/<hunt_id>/errors', {'strip_root_types': True})]
[(u'GET', u'/api/hunts/<hunt_id>/log', {'strip_root_types': True})]
[(u'GET', u'/api/hunts/<hunt_id>/output-plugins/<plugin_id>/errors', {'strip_root_types': True})]
[(u'GET', u'/api/hunts/<hunt_id>/output-plugins/<plugin_id>/logs', {'strip_root_types': True})]
[(u'GET', u'/api/hunts/<hunt_id>/output-plugins', {'strip_root_types': True})]
[(u'GET', u'/api/hunts/<hunt_id>/results', {'strip_root_types': True})]
[(u'GET', u'/api/hunts', {'strip_root_types': True})]
[(u'GET', u'/api/clients/kb-fields', {'strip_root_types': True})]
[(u'GET', u'/api/reflection/file-encodings', {'strip_root_types': True})]
[(u'GET', u'/api/output-plugins/all', {'strip_root_types': True})]
[(u'GET', u'/api/users/me/notifications/pending', {'strip_root_types': True})]
[(u'GET', u'/api/reflection/rdfvalue/all', {'strip_root_types': True})]
[(u'GET', u'/api/stats/reports', {'strip_root_types': True})]
[(u'PATCH', u'/api/cron-jobs/<cron_job_id>', {'strip_root_types': False})]
[(u'PATCH', u'/api/hunts/<hunt_id>', {'strip_root_types': False})]
[(u'POST', u'/api/clients/labels/remove', {'strip_root_types': True})]
[(u'GET', u'/api/clients', {'strip_root_types': True})]
[(u'POST', u'/api/users/me', {'strip_root_types': True})]
[(u'POST', u'/api/clients/<client_id>/vfs-update', {'strip_root_types': True})]
[(u'POST', u'/api/artifacts', {'strip_root_types': True})]

46. routing map has the method called and the associated metadata with it; 

47. note that     self._routing_maps_cache = utils.FastStore()

48. all methods exists in ApiCallRouterStub in api_call_router:e.g.

  @Category("Flows")
  @ArgsType(api_flow.ApiCreateFlowArgs)
  @ResultType(api_flow.ApiFlow)
  @Http("POST", "/api/clients/<client_id>/flows", strip_root_types=False)
  def CreateFlow(self, args, token=None):
    """Start a new flow on a given client."""
    raise NotImplementedError()

49. All existent flows that are with categories [others exists are mentioned underneath]: (76 flows);; GET THEM FROM ApiListFlowDescriptorsHandler in api_pugins/flow.py
ArtifactCollectorFlow
ArtifactFilesDownloaderFlow
CAEnroler
CacheGrep
CheckRunner
ChromeHistory
CleanCronJobs
CleanHunts
CleanInactiveClients
ClientAlertHandlerFlow
ClientArtifactCollector
ClientFileFinder
ClientStartupHandlerFlow
ClientVfsMigrationFlow
CollectRunKeyBinaries
CreateAndRunGenericHuntFlow
CreateGenericHuntFlow
DeleteGRRTempFiles
DiskVolumeInfo
DumpACPITable
DumpFlashImage
Enroler
ExecuteCommand
ExecutePythonHack
FetchBufferForSparseImage
FileFinder
FindFiles
FingerprintFile
FirefoxHistory
FlowBase
Foreman
GRRFlow
GRRHunt
GRRVersionBreakDown
GenericHunt
GetClientStats
GetClientStatsAuto
GetFile
GetMBR
Glob
Interrogate
InterrogateClientsCronFlow
KeepAlive
Kill
KnowledgeBaseInitializationFlow
LastAccessStats
LaunchBinary
ListDirectory
ListProcesses
ListVolumeShadowCopies
MakeNewAFF4SparseImage
MultiGetFile
NannyMessageHandlerFlow
Netstat
OSBreakDown
OnlineNotification
OsqueryFlow
PlistValueFilter
ProcessHuntResultCollectionsCronFlow
PurgeClientStats
RecursiveListDirectory
RegistryFinder
SampleHunt
SendFile
SystemRootSystemDriveFallbackFlow
TransferStore
Uninstall
UpdateClient
UpdateConfiguration
UpdateSparseImageChunks
UpdateVFSFile
VariableGenericHunt
WellKnownFlow
WindowsAllUsersProfileFallbackFlow
YaraDumpProcessMemory
YaraProcessScan

50. The classes for such names are the following:
<class 'abc.ArtifactCollectorFlow'>
<class 'abc.ArtifactFilesDownloaderFlow'>
<class 'abc.CAEnroler'>
<class 'abc.CacheGrep'>
<class 'abc.CheckRunner'>
<class 'abc.ChromeHistory'>
<class 'grr_response_server.flows.cron.data_retention.CleanCronJobs'>
<class 'grr_response_server.flows.cron.data_retention.CleanHunts'>
<class 'grr_response_server.flows.cron.data_retention.CleanInactiveClients'>
<class 'grr_response_server.flows.general.administrative.ClientAlertHandlerFlow'>
<class 'abc.ClientArtifactCollector'>
<class 'abc.ClientFileFinder'>
<class 'grr_response_server.flows.general.administrative.ClientStartupHandlerFlow'>
<class 'grr_response_server.flows.general.data_migration.ClientVfsMigrationFlow'>
<class 'abc.CollectRunKeyBinaries'>
<class 'grr_response_server.hunts.standard.CreateAndRunGenericHuntFlow'>
<class 'grr_response_server.hunts.standard.CreateGenericHuntFlow'>
<class 'abc.DeleteGRRTempFiles'>
<class 'abc.DiskVolumeInfo'>
<class 'abc.DumpACPITable'>
<class 'abc.DumpFlashImage'>
<class 'grr_response_server.flows.general.ca_enroller.Enroler'>
<class 'abc.ExecuteCommand'>
<class 'abc.ExecutePythonHack'>
<class 'abc.FetchBufferForSparseImage'>
<class 'abc.FileFinder'>
<class 'abc.FindFiles'>
<class 'abc.FingerprintFile'>
<class 'abc.FirefoxHistory'>
<class 'grr_response_server.flow.FlowBase'>
<class 'grr_response_server.flows.general.administrative.Foreman'>
<class 'grr_response_server.flow.GRRFlow'>
<class 'grr_response_server.hunts.implementation.GRRHunt'>
<class 'grr_response_server.flows.cron.system.GRRVersionBreakDown'>
<class 'grr_response_server.hunts.standard.GenericHunt'>
<class 'abc.GetClientStats'>
<class 'grr_response_server.flows.general.administrative.GetClientStatsAuto'>
<class 'abc.GetFile'>
<class 'abc.GetMBR'>
<class 'abc.Glob'>
<class 'abc.Interrogate'>
<class 'grr_response_server.flows.cron.system.InterrogateClientsCronFlow'>
<class 'abc.KeepAlive'>
<class 'abc.Kill'>
<class 'abc.KnowledgeBaseInitializationFlow'>
<class 'grr_response_server.flows.cron.system.LastAccessStats'>
<class 'abc.LaunchBinary'>
<class 'abc.ListDirectory'>
<class 'abc.ListProcesses'>
<class 'grr_response_server.flows.general.windows_vsc.ListVolumeShadowCopies'>
<class 'grr_response_server.flows.general.filesystem.MakeNewAFF4SparseImage'>
<class 'abc.MultiGetFile'>
<class 'grr_response_server.flows.general.administrative.NannyMessageHandlerFlow'>
<class 'abc.Netstat'>
<class 'grr_response_server.flows.cron.system.OSBreakDown'>
<class 'abc.OnlineNotification'>
<class 'abc.OsqueryFlow'>
::ffff:127.0.0.1 - - [02/Mar/2019 21:23:51] "HEAD /api/clients/C.1be17baa0aeb80b5/flows HTTP/1.1" 200 0
<class 'grr_response_server.flows.general.filetypes.PlistValueFilter'>
<class 'abc.ProcessHuntResultCollectionsCronFlow'>
<class 'grr_response_server.flows.cron.system.PurgeClientStats'>
<class 'abc.RecursiveListDirectory'>
<class 'abc.RegistryFinder'>
<class 'grr_response_server.hunts.standard.SampleHunt'>
<class 'abc.SendFile'>
<class 'abc.SystemRootSystemDriveFallbackFlow'>
<class 'grr_response_server.flows.general.transfer.TransferStore'>
<class 'abc.Uninstall'>
<class 'abc.UpdateClient'>
<class 'abc.UpdateConfiguration'>
<class 'abc.UpdateSparseImageChunks'>
<class 'grr_response_server.aff4_objects.aff4_grr.UpdateVFSFile'>
<class 'grr_response_server.hunts.standard.VariableGenericHunt'>
<class 'grr_response_server.flow.WellKnownFlow'>
<class 'abc.WindowsAllUsersProfileFallbackFlow'>
<class 'abc.YaraDumpProcessMemory'>
<class 'abc.YaraProcessScan'>


some flows are with no categoru:
<class 'grr_response_server.flows.cron.data_retention.CleanCronJobs'>
<class 'grr_response_server.flows.cron.data_retention.CleanHunts'>
<class 'grr_response_server.flows.cron.data_retention.CleanInactiveClients'>
<class 'grr_response_server.flows.general.administrative.ClientAlertHandlerFlow'>
<class 'grr_response_server.flows.general.administrative.ClientStartupHandlerFlow'>
<class 'grr_response_server.hunts.standard.CreateAndRunGenericHuntFlow'>
<class 'grr_response_server.hunts.standard.CreateGenericHuntFlow'>
<class 'grr_response_server.flows.general.ca_enroller.Enroler'>
<class 'abc.ExecuteCommand'>
<class 'grr_response_server.flow.FlowBase'>
<class 'grr_response_server.flows.general.administrative.Foreman'>
<class 'grr_response_server.flow.GRRFlow'>
<class 'grr_response_server.hunts.implementation.GRRHunt'>
<class 'grr_response_server.flows.cron.system.GRRVersionBreakDown'>
<class 'grr_response_server.hunts.standard.GenericHunt'>
<class 'grr_response_server.flows.general.administrative.GetClientStatsAuto'>
<class 'grr_response_server.flows.cron.system.InterrogateClientsCronFlow'>
<class 'grr_response_server.flows.cron.system.LastAccessStats'>
<class 'abc.MultiGetFile'>
<class 'grr_response_server.flows.general.administrative.NannyMessageHandlerFlow'>
<class 'grr_response_server.flows.cron.system.OSBreakDown'>
<class 'abc.ProcessHuntResultCollectionsCronFlow'>
<class 'grr_response_server.flows.cron.system.PurgeClientStats'>
<class 'grr_response_server.hunts.standard.SampleHunt'>
<class 'abc.SystemRootSystemDriveFallbackFlow'>
<class 'grr_response_server.flows.general.transfer.TransferStore'>
<class 'abc.UpdateConfiguration'>
<class 'grr_response_server.aff4_objects.aff4_grr.UpdateVFSFile'>
<class 'grr_response_server.hunts.standard.VariableGenericHunt'>
<class 'grr_response_server.flow.WellKnownFlow'>
<class 'abc.WindowsAllUsersProfileFallbackFlow'>

51. flow descriptors and all fields of it:
<class 'abc.ArtifactCollectorFlow'>
message ApiFlowDescriptor {
 args_type : u'ArtifactCollectorFlowArgs'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Collectors'
 default_args :   <ArtifactCollectorFlowArgs('message ArtifactCollectorFlowArgs {\n}')>
 doc : u'Flow that takes a list of artifacts and collects them.\n\n  This flow is the core of the Artifact implementation for GRR. Artifacts are\n  defined using a standardized data format that includes what to collect and\n  how to process the things collected. This flow takes that data driven format\n  and makes it useful.\n\n  The core functionality of Artifacts is split into ArtifactSources and\n  Processors.\n\n  An Artifact defines a set of ArtifactSources that are used to retrieve data\n  from the client. These can specify collection of files, registry keys, command\n  output and others. The first part of this flow "Collect" handles running those\n  collections by issuing GRR flows and client actions.\n\n  The results of those are then collected and GRR searches for Processors that\n  know how to process the output of the ArtifactSources. The Processors all\n  inherit from the Parser class, and each Parser specifies which Artifacts it\n  knows how to process.\n\n  So this flow hands off the collected rdfvalue results to the Processors which\n  then return modified or different rdfvalues. These final results are then\n  either:\n  1. Sent to the calling flow.\n  2. Written to a collection.\n  \n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="ArtifactCollectorFlow", artifact_list=artifact_list, use_tsk=use_tsk, split_output_by_artifact=split_output_by_artifact, knowledge_base=knowledge_base, error_on_no_results=error_on_no_results, apply_parsers=apply_parsers, max_file_size=max_file_size, dependencies=dependencies, ignore_interpolation_errors=ignore_interpolation_errors, recollect_knowledge_base=recollect_knowledge_base)\n\n  Args:\n    apply_parsers\n      description: If True, apply any relevant parser to the collected data. If False, return the raw collected data e.g Files or Registry Keys.\n      type: RDFBool\n      default: 1\n\n    artifact_list\n      description: A list of Artifact class names.\n      type: \n      default: None\n\n    dependencies\n      description: Specifies how dependencies should be handled.\n      type: EnumNamedValue\n      default: USE_CACHED\n\n    error_on_no_results\n      description: If True, an artifact returning no results will raise a hard error. This is useful where you always expect results.\n      type: RDFBool\n      default: 0\n\n    ignore_interpolation_errors\n      description: If true, don\'t die if %%users.homedir%% and similar fail to expand. It\'s common on windows for some user attributes to be missing if users have never logged in. Enable this when you have multiple artifacts or paths and want to report partial results.\n      type: RDFBool\n      default: 0\n\n    knowledge_base\n      description: An optional knowledge base to use, if not specified we retrieve one from the client object.\n      type: KnowledgeBase\n      default: None\n\n    max_file_size\n      description: The maximum size of files we will download in bytes, 500MB by default.\n      type: ByteSize\n      default: 500000000\n\n    recollect_knowledge_base\n      description: Whether the dependencies should be collected as well or the interrogation flow is used.\n      type: RDFBool\n      default: 0\n\n    split_output_by_artifact\n      description: If True, use output as a directory and write a separate collection for each artifact collected.\n      type: RDFBool\n      default: 0\n\n    use_tsk\n      description: Whether raw filesystem access should be used.\n      type: RDFBool\n      default: 0\n'
 name : u'ArtifactCollectorFlow'
}
<class 'abc.ArtifactFilesDownloaderFlow'>
message ApiFlowDescriptor {
 args_type : u'ArtifactFilesDownloaderFlowArgs'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'Collectors'
 default_args :   <ArtifactFilesDownloaderFlowArgs('message ArtifactFilesDownloaderFlowArgs {\n}')>
 doc : u'Flow that downloads files referenced by collected artifacts.\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="ArtifactFilesDownloaderFlow", artifact_list=artifact_list, use_tsk=use_tsk, max_file_size=max_file_size)\n\n  Args:\n    artifact_list\n      description: A list of Artifact class names.\n      type: \n      default: None\n\n    max_file_size\n      description: The maximum size of files we will download in bytes, 500MB by default.\n      type: ByteSize\n      default: 500000000\n\n    use_tsk\n      description: Whether raw filesystem access should be used.\n      type: RDFBool\n      default: 0\n'
 name : u'ArtifactFilesDownloaderFlow'
}
<class 'abc.CAEnroler'>
<class 'abc.CacheGrep'>
message ApiFlowDescriptor {
 args_type : u'CacheGrepArgs'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Browser'
 default_args :   <CacheGrepArgs('message CacheGrepArgs {\n}')>
 doc : u'Grep the browser profile directories for a regex.\n\n  This will check Chrome, Firefox and Internet Explorer profile directories.\n  Note that for each directory we get a maximum of 50 hits returned.\n  \n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="CacheGrep", grep_users=grep_users, pathtype=pathtype, data_regex=data_regex, check_chrome=check_chrome, check_firefox=check_firefox, check_ie=check_ie)\n\n  Args:\n    check_chrome\n      description: Check Chrome\n      type: RDFBool\n      default: 1\n\n    check_firefox\n      description: Check Firefox\n      type: RDFBool\n      default: 1\n\n    check_ie\n      description: Check Internet Explorer (Not implemented yet)\n      type: RDFBool\n      default: 1\n\n    data_regex\n      description: A regular expression to search for.\n      type: RegularExpression\n      default: None\n\n    grep_users\n      description: A list of users to check. Default all users on the system.\n      type: \n      default: None\n\n    pathtype\n      description: Type of path access to use.\n      type: EnumNamedValue\n      default: OS\n'
 name : u'CacheGrep'
}
<class 'abc.CheckRunner'>
message ApiFlowDescriptor {
 args_type : u'CheckFlowArgs'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Checks'
 default_args :   <CheckFlowArgs('message CheckFlowArgs {\n}')>
 doc : u'This flow runs checks on a host.\n\n  CheckRunner:\n  - Identifies what checks should be run for a host.\n  - Identifies the artifacts that need to be collected to perform those checks.\n  - Orchestrates collection of the host data.\n  - Routes host data to the relevant checks.\n  - Returns check data ready for reporting.\n  \n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="CheckRunner", only_os=only_os, only_cpe=only_cpe, only_label=only_label, max_findings=max_findings, restrict_checks=restrict_checks)\n\n  Args:\n    max_findings\n      description: Summarize checks with more than N individual findings.\n      type: \n      default: None\n\n    only_cpe\n      description: Limit checks to hosts with cpe strings.\n      type: \n      default: None\n\n    only_label\n      description: Lim::ffff:127.0.0.1 - - [02/Mar/2019 21:27:03] "HEAD /api/clients/C.1be17baa0aeb80b5/flows HTTP/1.1" 200 0
it checks to hosts with label strings.\n      type: \n      default: None\n\n    only_os\n      description: Limit checks to hosts of OS type(s) [Linux|OSX|Windows]\n      type: \n      default: None\n\n    restrict_checks\n      description: Only run checks with the specified check_ids.\n      type: \n      default: None\n'
 friendly_name : u'Run Checks'
 name : u'CheckRunner'
}
<class 'abc.ChromeHistory'>
message ApiFlowDescriptor {
 args_type : u'ChromeHistoryArgs'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Browser'
 default_args :   <ChromeHistoryArgs('message ChromeHistoryArgs {\n}')>
 doc : u'Retrieve and analyze the chrome history for a machine.\n\n  Default directories as per:\n    http://www.chromium.org/user-experience/user-data-directory\n\n  Windows XP\n  Google Chrome:\n  c:\\\\Documents and Settings\\\\<username>\\\\Local Settings\\\\Application Data\\\\\n    Google\\\\Chrome\\\\User Data\\\\Default\n\n  Windows 7 or Vista\n  c:\\\\Users\\\\<username>\\\\AppData\\\\Local\\\\Google\\\\Chrome\\\\User Data\\\\Default\n\n  Mac OS X\n  /Users/<user>/Library/Application Support/Google/Chrome/Default\n\n  Linux\n  /home/<user>/.config/google-chrome/Default\n  \n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="ChromeHistory", pathtype=pathtype, get_archive=get_archive, username=username, history_path=history_path)\n\n  Args:\n    get_archive\n      description: Should we get Archived History as well (3 months old).\n      type: RDFBool\n      default: 0\n\n    history_path\n      description: Path to a profile directory that contains a History file.\n      type: RDFString\n      default: \n\n    pathtype\n      description: Type of path access to use.\n      type: EnumNamedValue\n      default: OS\n\n    username\n      description: The user to get Chrome history for. If history_path is not set this will be used to guess the path to the history files. Can be in form DOMAIN\\user.\n      type: RDFString\n      default: \n'
 name : u'ChromeHistory'
}
<class 'grr_response_server.flows.cron.data_retention.CleanCronJobs'>
<class 'grr_response_server.flows.cron.data_retention.CleanHunts'>
<class 'grr_response_server.flows.cron.data_retention.CleanInactiveClients'>
<class 'grr_response_server.flows.general.administrative.ClientAlertHandlerFlow'>
<class 'abc.ClientArtifactCollector'>
message ApiFlowDescriptor {
 args_type : u'ArtifactCollectorFlowArgs'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Collectors'
 default_args :   <ArtifactCollectorFlowArgs('message ArtifactCollectorFlowArgs {\n}')>
 doc : u'A client side artifact collector.\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="ClientArtifactCollector", artifact_list=artifact_list, use_tsk=use_tsk, split_output_by_artifact=split_output_by_artifact, knowledge_base=knowledge_base, error_on_no_results=error_on_no_results, apply_parsers=apply_parsers, max_file_size=max_file_size, dependencies=dependencies, ignore_interpolation_errors=ignore_interpolation_errors, recollect_knowledge_base=recollect_knowledge_base)\n\n  Args:\n    apply_parsers\n      description: If True, apply any relevant parser to the collected data. If False, return the raw collected data e.g Files or Registry Keys.\n      type: RDFBool\n      default: 1\n\n    artifact_list\n      description: A list of Artifact class names.\n      type: \n      default: None\n\n    dependencies\n      description: Specifies how dependencies should be handled.\n      type: EnumNamedValue\n      default: USE_CACHED\n\n    error_on_no_results\n      description: If True, an artifact returning no results will raise a hard error. This is useful where you always expect results.\n      type: RDFBool\n      default: 0\n\n    ignore_interpolation_errors\n      description: If true, don\'t die if %%users.homedir%% and similar fail to expand. It\'s common on windows for some user attributes to be missing if users have never logged in. Enable this when you have multiple artifacts or paths and want to report partial results.\n      type: RDFBool\n      default: 0\n\n    knowledge_base\n      description: An optional knowledge base to use, if not specified we retrieve one from the client object.\n      type: KnowledgeBase\n      default: None\n\n    max_file_size\n      description: The maximum size of files we will download in bytes, 500MB by default.\n      type: ByteSize\n      default: 500000000\n\n    recollect_knowledge_base\n      description: Whether the dependencies should be collected as well or the interrogation flow is used.\n      type: RDFBool\n      default: 0\n\n    split_output_by_artifact\n      description: If True, use output as a directory and write a separate collection for each artifact collected.\n      type: RDFBool\n      default: 0\n\n    use_tsk\n      description: Whether raw filesystem access should be used.\n      type: RDFBool\n      default: 0\n'
 name : u'ClientArtifactCollector'
}
<class 'abc.ClientFileFinder'>
message ApiFlowDescriptor {
 args_type : u'FileFinderArgs'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Filesystem'
 default_args :   <FileFinderArgs('message FileFinderArgs {\n}')>
 doc : u'A client side file finder flow.\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="ClientFileFinder", paths=paths, pathtype=pathtype, conditions=conditions, action=action, process_non_regular_files=process_non_regular_files, follow_links=follow_links, xdev=xdev)\n\n  Args:\n    action\n      description: \n      type: FileFinderAction\n      default: None\n\n    conditions\n      description: These conditions will be applied to all files that match the path arguments.\n      type: \n      default: None\n\n    follow_links\n      description: Should symbolic links be followed in recursive directory listings.\n      type: RDFBool\n      default: 0\n\n    paths\n      description: A path to glob that can contain %% expansions.\n      type: \n      default: None\n\n    pathtype\n      description: Path type to glob in.\n      type: EnumNamedValue\n      default: OS\n\n    process_non_regular_files\n      description: Look both into regular files and non-regular files (devices, named pipes, sockets). NOTE: This is very dangerous and should be used with care.\n      type: RDFBool\n      default: 0\n\n    xdev\n      description: Behavior when ecountering device boundaries while doing recursive searches.\n      type: EnumNamedValue\n      default: LOCAL\n'
 friendly_name : u'Client Side File Finder'
 name : u'ClientFileFinder'
}
<class 'grr_response_server.flows.general.administrative.ClientStartupHandlerFlow'>
<class 'grr_response_server.flows.general.data_migration.ClientVfsMigrationFlow'>
message ApiFlowDescriptor {
 args_type : u'EmptyFlowArgs'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'Administrative'
 default_args :   <EmptyFlowArgs('message EmptyFlowArgs {\n}')>
 doc : u'None\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="ClientVfsMigrationFlow", )\n\n  Args: None'
 name : u'ClientVfsMigrationFlow'
}
<class 'abc.CollectRunKeyBinaries'>
message ApiFlowDescriptor {
 args_type : u'EmptyFlowArgs'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Registry'
 default_args :   <EmptyFlowArgs('message EmptyFlowArgs {\n}')>
 doc : u'Collect the binaries used by Run and RunOnce keys on the system.\n\n  We use the RunKeys artifact to get RunKey command strings for all users and\n  System. This flow guesses file paths from the strings, expands any\n  windows system environment variables, and attempts to retrieve the files.\n  \n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="CollectRunKeyBinaries", )\n\n  Args: None'
 name : u'CollectRunKeyBinaries'
}
<class 'grr_response_server.hunts.standard.CreateAndRunGenericHuntFlow'>
<class 'grr_response_server.hunts.standard.CreateGenericHuntFlow'>
<class 'abc.DeleteGRRTempFiles'>
message ApiFlowDescriptor {
 args_type : u'DeleteGRRTempFilesArgs'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'Administrative'
 default_args :   <DeleteGRRTempFilesArgs('message DeleteGRRTempFilesArgs {\n}')>
 doc : u'Delete all the GRR temp files in path.\n\n  If path is a directory, look in the top level for filenames beginning with\n  Client.tempfile_prefix, and delete them.\n\n  If path is a regular file and starts with Client.tempfile_prefix, delete it.\n  \n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="DeleteGRRTempFiles", pathspec=pathspec)\n\n  Args:\n    pathspec\n      description: The pathspec target for deletion.If path is a directory, look in the top level for filenames beginning with Client.tempfile_prefix, and delete them. If path is a regular file and starts with Client.tempfile_prefix, delete it.\n      type: PathSpec\n      default: None\n'
 name : u'DeleteGRRTempFiles'
}
<class 'abc.DiskVolumeInfo'>
message ApiFlowDescriptor {
 args_type : u'DiskVolumeInfoArgs'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'Filesystem'
 default_args :   <DiskVolumeInfoArgs('message DiskVolumeInfoArgs {\n}')>
 doc : u'Get disk volume info for a given path.\n\n  On linux and OS X we call StatFS on each path and return the results. For\n  windows we collect all the volume information and filter it using the drive\n  letters in the supplied path list.\n  \n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="DiskVolumeInfo", path_list=path_list, pathtype=pathtype)\n\n  Args:\n    path_list\n      description: List of paths.\n      type: \n      default: None\n\n    pathtype\n      description: Type of path. Only OS is currently supported.\n      type: EnumNamedValue\n      default: OS\n'
 name : u'DiskVolumeInfo'
}
<class 'abc.DumpACPITable'>
message ApiFlowDescriptor {
 args_type : u'DumpACPITableArgs'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Collectors'
 default_args :   <DumpACPITableArgs('message DumpACPITableArgs {\n}')>
 doc : u'Flow to retrieve ACPI tables.\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="DumpACPITable", logging=logging, table_signature_list=table_signature_list)\n\n  Args:\n    logging\n      description: If the logging is set to true, the client sends log, including Chipsec\'s log.\n      type: RDFBool\n      default: 0\n\n    table_signature_list\n      description: Signature of ACPI tables to be dumped.\n      type: \n      default: None\n'
 name : u'DumpACPITable'
}
<class 'abc.DumpFlashImage'>
message ApiFlowDescriptor {
 args_type : u'DumpFlashImageArgs'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Collectors'
 default_args :   <DumpFlashImageArgs('message DumpFlashImageArgs {\n}')>
 doc : u'Dump Flash image (BIOS).\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="DumpFlashImage", log_level=log_level, chunk_size=chunk_size, notify_syslog=notify_syslog)\n\n  Args:\n    chunk_size\n      description: A heartbeat will be emitted every chunk_size.This could be reduced in case the process times out.\n      type: RDFInteger\n      default: 65536\n\n    log_level\n      description: Set the log level. If set, the log returned will include additional information reported by Chipsec.\n      type: RDFInteger\n      default: 0\n\n    notify_syslog\n      description: If true, a message will be written by the client to the syslog before running the action. This can be used for debugging in case the client crashes during the image dumping process.\n      type: RDFBool\n      default: 0\n'
 name : u'DumpFlashImage'
}
<class 'grr_response_server.flows.general.ca_enroller.Enroler'>
<class 'abc.ExecuteCommand'>
<class 'abc.ExecutePythonHack'>
message ApiFlowDescriptor {
 args_type : u'ExecutePythonHackArgs'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'Administrative'
 default_args :   <ExecutePythonHackArgs('message ExecutePythonHackArgs {\n}')>
 doc : u'Execute a signed python hack on a client.\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="ExecutePythonHack", hack_name=hack_name, py_args=py_args)\n\n  Args:\n    hack_name\n      description: Relative path to the hack to execute.\n      type: RDFString\n      default: \n\n    py_args\n      description: Python Hack Arguments.\n      type: Dict\n      default: None\n'
 name : u'ExecutePythonHack'
}
<class 'abc.FetchBufferForSparseImage'>
message ApiFlowDescriptor {
 args_type : u'FetchBufferForSparseImageArgs'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'Filesystem'
 default_args :   <FetchBufferForSparseImageArgs('message FetchBufferForSparseImageArgs {\n}')>
 doc : u'Reads data from a client-side file, specified by a length and offset.\n\n  This data is written to an AFF4SparseImage object. Note that\n  more data than is requested may be read since we align reads to chunks.\n  \n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="FetchBufferForSparseImage", file_urn=file_urn, length=length, offset=offset)\n\n  Args:\n    file_urn\n      description: The URN of the sparse image to update\n      type: RDFURN\n      default: None\n\n    length\n      description: \n      type: RDFInteger\n      default: 0\n\n    offset\n      description: \n      type: RDFInteger\n      default: 0\n'
 name : u'FetchBufferForSparseImage'
}
<class 'abc.FileFinder'>
message ApiFlowDescriptor {
 args_type : u'FileFinderArgs'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Filesystem'
 default_args :   <FileFinderArgs('message FileFinderArgs {\n}')>
 doc : u'This flow looks for files matching given criteria and acts on them.\n\n  FileFinder searches for files that match glob expressions.  The "action"\n  (e.g. Download) is applied to files that match all given "conditions".\n  Matches are then written to the results collection. If there are no\n  "conditions" specified, "action" is just applied to all found files.\n  \n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="FileFinder", paths=paths, pathtype=pathtype, conditions=conditions, action=action, process_non_regular_files=process_non_regular_files, follow_links=follow_links, xdev=xdev)\n\n  Args:\n    action\n      description: \n      type: FileFinderAction\n      default: None\n\n    conditions\n      description: These conditions will be applied to all files that match the path arguments.\n      type: \n      default: None\n\n    follow_links\n      description: Should symbolic links be followed in recursive directory listings.\n      type: RDFBool\n      default: 0\n\n    paths\n      description: A path to glob that can contain %% expansions.\n      type: \n      default: None\n\n    pathtype\n      description: Path type to glob in.\n      type: EnumNamedValue\n      default: OS\n\n    process_non_regular_files\n      description: Look both into regular files and non-regular files (devices, named pipes, sockets). NOTE: This is very dangerous and should be used with care.\n      type: RDFBool\n      default: 0\n\n    xdev\n      description: Behavior when ecountering device boundaries while doing recursive searches.\n      type: EnumNamedValue\n      default: LOCAL\n'
 friendly_name : u'File Finder'
 name : u'FileFinder'
}
<class 'abc.FindFiles'>
message ApiFlowDescriptor {
 args_type : u'FindFilesArgs'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'Filesystem'
 default_args :   <FindFilesArgs('message FindFilesArgs {\n}')>
 doc : u'Find files on the client.\n\n    The logic is:\n    - Find files under "Path"\n    - Filter for files with os.path.basename matching "Path Regular Expression"\n    - Filter for files with sizes between min and max limits\n    - Filter for files that contain "Data Regular Expression" in the first 1MB\n        of file data\n    - Return a StatEntry rdfvalue for each of the results\n\n    Path and data regexes, and file size limits are optional. Don"t encode path\n    information in the regex.  See correct usage below.\n\n    Example:\n\n    Path="/usr/local"\n    Path Regular Expression="admin"\n\n    Match: "/usr/local/bin/admin"      (file)\n    Match: "/usr/local/admin"          (directory)\n    No Match: "/usr/admin/local/blah"\n\n    The result from this flow is a list of StatEntry objects, one for\n    each file matching the criteria. Matching files will not be\n    downloaded by this flow, only the metadata of the file is fetched.\n\n  Returns to parent flow:\n    rdf_client_fs.StatEntry objects for each found file.\n  \n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="FindFiles", findspec=findspec)\n\n  Args:\n    findspec\n      description: A find operation specification.\n      type: FindSpec\n      default: None\n'
 friendly_name : u'Find Files'
 name : u'FindFiles'
}
<class 'abc.FingerprintFile'>
message ApiFlowDescriptor {
 args_type : u'FingerprintFileArgs'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'Filesystem'
 default_args :   <FingerprintFileArgs('message FingerprintFileArgs {\n}')>
 doc : u'Retrieve all fingerprints of a file.\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="FingerprintFile", pathspec=pathspec)\n\n  Args:\n    pathspec\n      description: The file path to fingerprint.\n      type: PathSpec\n      default: None\n'
 name : u'FingerprintFile'
}
<class 'abc.FirefoxHistory'>
message ApiFlowDescriptor {
 args_type : u'FirefoxHistoryArgs'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Browser'
 default_args :   <FirefoxHistoryArgs('message FirefoxHistoryArgs {\n}')>
 doc : u'Retrieve and analyze the Firefox history for a machine.\n\n  Default directories as per:\n    http://www.forensicswiki.org/wiki/Mozilla_Firefox_3_History_File_Format\n\n  Windows XP\n    C:\\\\Documents and Settings\\\\<username>\\\\Application Data\\\\Mozilla\\\\\n      Firefox\\\\Profiles\\\\<profile folder>\\\\places.sqlite\n\n  Windows Vista\n    C:\\\\Users\\\\<user>\\\\AppData\\\\Roaming\\\\Mozilla\\\\Firefox\\\\Profiles\\\\\n      <profile folder>\\\\places.sqlite\n\n  GNU/Linux\n    /home/<user>/.mozilla/firefox/<profile folder>/places.sqlite\n\n  Mac OS X\n    /Users/<user>/Library/Application Support/Firefox/Profiles/\n      <profile folder>/places.sqlite\n  \n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="FirefoxHistory", pathtype=pathtype, get_archive=get_archive, username=username, history_path=history_path)\n\n  Args:\n    get_archive\n      description: Should we get Archived History as well (3 months old).\n      type: RDFBool\n      default: 0\n\n    history_path\n      description: Path to a profile directory that contains a History file.\n      type: RDFString\n      default: \n\n    pathtype\n      description: Type of path access to use.\n      type: EnumNamedValue\n      default: OS\n\n    username\n      description: The user to get history for. If history_path is not set this will be used to guess the path to the history files. Can be in form DOMAIN\\user.\n      type: RDFString\n      default: \n'
 name : u'FirefoxHistory'
}
<class 'grr_response_server.flow.FlowBase'>
<class 'grr_response_server.flows.general.administrative.Foreman'>
<class 'grr_response_server.flow.GRRFlow'>
<class 'grr_response_server.hunts.implementation.GRRHunt'>
<class 'grr_response_server.flows.cron.system.GRRVersionBreakDown'>
<class 'grr_response_server.hunts.standard.GenericHunt'>
<class 'abc.GetClientStats'>
message ApiFlowDescriptor {
 args_type : u'EmptyFlowArgs'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'Administrative'
 default_args :   <EmptyFlowArgs('message EmptyFlowArgs {\n}')>
 doc : u'This flow retrieves information about the GRR client process.\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="GetClientStats", )\n\n  Args: None'
 name : u'GetClientStats'
}
<class 'grr_response_server.flows.general.administrative.GetClientStatsAuto'>
<class 'abc.GetFile'>
message ApiFlowDescriptor {
 args_type : u'GetFileArgs'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'Filesystem'
 default_args :   <GetFileArgs('message GetFileArgs {\n pathspec :   message PathSpec {\n     pathtype : OS\n    }\n}')>
 doc : u'An efficient file transfer mechanism (deprecated, use MultiGetFile).\n\n  This flow is deprecated in favor of MultiGetFile, but kept for now for use by\n  MemoryCollector since the buffer hashing performed by MultiGetFile is\n  pointless for memory acquisition.\n\n  GetFile can also retrieve content from device files that report a size of 0 in\n  stat when read_length is specified.\n\n  Returns to parent flow:\n    A PathSpec.\n  \n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="GetFile", pathspec=pathspec, read_length=read_length, ignore_stat_failure=ignore_stat_failure)\n\n  Args:\n    ignore_stat_failure\n      description: Ignore stat failures and try to read anyway. Disable for windows devices.\n      type: RDFBool\n      default: 0\n\n    pathspec\n      description: The pathspec for the file to retrieve.\n      type: PathSpec\n      default: None\n\n    read_length\n      description: The amount of data to read from the file. If 0 we use the value from a stat call.\n      type: RDFInteger\n      default: 0\n'
 name : u'GetFile'
}
<class 'abc.GetMBR'>
message ApiFlowDescriptor {
 args_type : u'GetMBRArgs'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Filesystem'
 default_args :   <GetMBRArgs('message GetMBRArgs {\n}')>
 doc : u'A flow to retrieve the MBR.\n\n  Returns to parent flow:\n    The retrieved MBR.\n  \n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="GetMBR", length=length)\n\n  Args:\n    length\n      description: The length of the MBR buffer to read.\n      type: RDFInteger\n      default: 4096\n'
 name : u'GetMBR'
}
<class 'abc.Glob'>
message ApiFlowDescriptor {
 args_type : u'GlobArgs'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'Filesystem'
 default_args :   <GlobArgs('message GlobArgs {\n}')>
 doc : u'Glob the filesystem for patterns.\n\n  Returns:\n    StatEntry messages, one for each matching file.\n  \n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="Glob", paths=paths, pathtype=pathtype, root_path=root_path, process_non_regular_files=process_non_regular_files)\n\n  Args:\n    paths\n      description: A list of paths to glob that supports: ** path recursion, * wildcards and %% expansions.\n      type: \n      default: None\n\n    pathtype\n      description: Type of access to glob in.\n      type: EnumNamedValue\n      default: OS\n\n    process_non_regular_files\n      description: Work with all kinds of files - not only with regular ones.NOTE: This is very dangerous and should be used with care, see MemoryCollector as an example.\n      type: RDFBool\n      default: 0\n\n    root_path\n      description: The root path to begin the glob.  Users should almost never need to change this. root_path.pathtype is unused in favor of pathtype to allow it to be modified by users.\n      type: PathSpec\n      default: None\n'
 name : u'Glob'
}
<class 'abc.Interrogate'>
message ApiFlowDescriptor {
 args_type : u'InterrogateArgs'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Administrative'
 default_args :   <InterrogateArgs('message InterrogateArgs {\n}')>
 doc : u'Interrogate various things about the host.\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="Interrogate", lightweight=lightweight)\n\n  Args:\n    lightweight\n      description: Perform a light weight version of the interrogate.\n      type: RDFBool\n      default: 1\n'
 name : u'Interrogate'
}
<class 'grr_response_server.flows.cron.system.InterrogateClientsCronFlow'>
<class 'abc.KeepAlive'>
message ApiFlowDescriptor {
 args_type : u'KeepAliveArgs'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Administrative'
 default_args :   <KeepAliveArgs('message KeepAliveArgs {\n}')>
 doc : u'Requests that the clients stays alive for a period of time.\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="KeepAlive", duration=duration)\n\n  Args:\n    duration\n      description: Until when should the client stay in the fast poll mode.\n      type: Duration\n      default: 3600\n'
 name : u'KeepAlive'
}
<class 'abc.Kill'>
message ApiFlowDescriptor {
 args_type : u'EmptyFlowArgs'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'Administrative'
 default_args :   <EmptyFlowArgs('message EmptyFlowArgs {\n}')>
 doc : u'Terminate a running client (does not disable, just kill).\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="Kill", )\n\n  Args: None'
 name : u'Kill'
}
<class 'abc.KnowledgeBaseInitializationFlow'>
message ApiFlowDescriptor {
 args_type : u'KnowledgeBaseInitializationArgs'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'Collectors'
 default_args :   <KnowledgeBaseInitializationArgs('message KnowledgeBaseInitializationArgs {\n}')>
 doc : u'Flow that atttempts to initialize the knowledge base.\n\n  This flow processes all artifacts specified by the\n  Artifacts.knowledge_base config. We determine what knowledgebase\n  attributes are required, collect them, and return a filled\n  knowledgebase.\n\n  We don\'t try to fulfill dependencies in the tree order, the\n  reasoning is that some artifacts may fail, and some artifacts\n  provide the same dependency.\n\n  Instead we take an iterative approach and keep requesting artifacts\n  until all dependencies have been met.  If there is more than one\n  artifact that provides a dependency we will collect them all as they\n  likely have different performance characteristics, e.g. accuracy and\n  client impact.\n  \n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="KnowledgeBaseInitializationFlow", require_complete=require_complete, lightweight=lightweight)\n\n  Args:\n    lightweight\n      description: If true skip all heavyweight artifacts defined in Artifacts.knowledge_base_heavyweight.\n      type: RDFBool\n      default: 1\n\n    require_complete\n      description: If true require all dependencies to be complete.  Raise if any are missing.\n      type: RDFBool\n      default: 1\n'
 name : u'KnowledgeBaseInitializationFlow'
}
<class 'grr_response_server.flows.cron.system.LastAccessStats'>
<class 'abc.LaunchBinary'>
message ApiFlowDescriptor {
 args_type : u'LaunchBinaryArgs'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'Administrative'
 default_args :   <LaunchBinaryArgs('message LaunchBinaryArgs {\n}')>
 doc : u'Launch a signed binary on a client.\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="LaunchBinary", binary=binary, command_line=command_line)\n\n  Args:\n    binary\n      description: The URN of the binary to execute.\n      type: RDFURN\n      default: None\n\n    command_line\n      description: Binary Arguments as a shell command line.\n      type: RDFString\n      default: \n'
 name : u'LaunchBinary'
}
<class 'abc.ListDirectory'>
message ApiFlowDescriptor {
 args_type : u'ListDirectoryArgs'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'Filesystem'
 default_args :   <ListDirectoryArgs('message ListDirectoryArgs {\n}')>
 doc : u'List files in a directory.\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="ListDirectory", pathspec=pathspec)\n\n  Args:\n    pathspec\n      description: The pathspec for the directory to list.\n      type: PathSpec\n      default: None\n'
 name : u'ListDirectory'
}
<class 'abc.ListProcesses'>
message ApiFlowDescriptor {
 args_type : u'ListProcessesArgs'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Processes'
 default_args :   <ListProcessesArgs('message ListProcessesArgs {\n}')>
 doc : u'List running processes on a system.\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="ListProcesses", filename_regex=filename_regex, fetch_binaries=fetch_binaries, connection_states=connection_states)\n\n  Args:\n    connection_states\n      description: Network connection states to match. If a process has any network connections in any status listed here, it will be considered a match\n      type: \n      default: None\n\n    fetch_binaries\n      description: \n      type: RDFBool\n      default: 0\n\n    filename_regex\n      description: Regex used to filter the list of processes.\n      type: RegularExpression\n      default: .\n'
 name : u'ListProcesses'
}
<class 'grr_response_server.flows.general.windows_vsc.ListVolumeShadowCopies'>
message ApiFlowDescriptor {
 args_type : u'EmptyFlowArgs'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Filesystem'
 default_args :   <EmptyFlowArgs('message EmptyFlowArgs {\n}')>
 doc : u'List the Volume Shadow Copies on the client.\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="ListVolumeShadowCopies", )\n\n  Args: None'
 name : u'ListVolumeShadowCopies'
}
<class 'grr_response_server.flows.general.filesystem.MakeNewAFF4SparseImage'>
message ApiFlowDescriptor {
 args_type : u'MakeNewAFF4SparseImageArgs'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'Filesystem'
 default_args :   <MakeNewAFF4SparseImageArgs('message MakeNewAFF4SparseImageArgs {\n}')>
 doc : u'Gets a new file from the client, possibly as an AFF4SparseImage.\n\n  If the filesize is >= the size threshold, then we get the file as an empty\n  AFF4SparseImage, otherwise we just call GetFile, which gets the complete file.\n\n  We do the check to see if the file is big enough to get as an AFF4SparseImage\n  in this flow so we don\'t need to do another round trip to the client.\n\n  Args:\n    pathspec: Pathspec of the file to look at.\n    size_threshold: If the file is bigger than this size, we\'ll get it as an\n      empty AFF4SparseImage, otherwise we\'ll just download the whole file as\n      usual with GetFile.\n  \n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="MakeNewAFF4SparseImage", pathspec=pathspec, size_threshold=size_threshold)\n\n  Args:\n    pathspec\n      description: \n      type: PathSpec\n      default: None\n\n    size_threshold\n      description: \n      type: RDFInteger\n      default: 0\n'
 name : u'MakeNewAFF4SparseImage'
}
<class 'abc.MultiGetFile'>
<class 'grr_response_server.flows.general.administrative.NannyMessageHandlerFlow'>
<class 'abc.Netstat'>
message ApiFlowDescriptor {
 args_type : u'NetstatArgs'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Network'
 default_args :   <NetstatArgs('message NetstatArgs {\n}')>
 doc : u'List active network connections on a system.\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="Netstat", listening_only=listening_only)\n\n  Args:\n    listening_only\n      description: If set, only listening connections are returned.\n      type: RDFBool\n      default: 0\n'
 name : u'Netstat'
}
<class 'grr_response_server.flows.cron.system.OSBreakDown'>
<class 'abc.OnlineNotification'>
message ApiFlowDescriptor {
 args_type : u'OnlineNotificationArgs'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Administrative'
 default_args :   <OnlineNotificationArgs('message OnlineNotificationArgs {\n email : DomainEmailAddress:\n    admin@localhost\n}')>
 doc : u'Notifies by email when a client comes online in GRR.\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="OnlineNotification", email=email)\n\n  Args:\n    email\n      description: Email address to send to. If not set, mail will be sent to the logged in user.\n      type: DomainEmailAddress\n      default: None\n'
 name : u'OnlineNotification'
}
<class 'abc.OsqueryFlow'>
message ApiFlowDescriptor {
 args_type : u'OsqueryArgs'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Collectors'
 default_args :   <OsqueryArgs('message OsqueryArgs {\n}')>
 doc : u'A flow mixin wrapping the osquery client action.\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="OsqueryFlow", queries=queries)\n\n  Args:\n    queries\n      description: \n      type: \n      default: None\n'
 friendly_name : u'osquery'
 name : u'OsqueryFlow'
}
<class 'grr_response_server.flows.general.filetypes.PlistValueFilter'>
message ApiFlowDescriptor {
 args_type : u'PlistValueFilterArgs'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'FileTypes'
 default_args :   <PlistValueFilterArgs('message PlistValueFilterArgs {\n}')>
 doc : u'Obtains values from a plist based on a context and a query filter.\n\n  This function will parse a plist. Obtain all the values under the path given\n  in context and then filter each of them against the given query and return\n  only these that match. I.e:\n\n  plist = {\n    \'values\': [13, 14, 15]\n    \'items\':\n      [\n        {\'name\': \'John\',\n         \'age\': 33,\n         \'children\': [\'John\', \'Phil\'],\n         },\n        {\'name\': \'Mike\',\n          \'age\': 24,\n          \'children\': [],\n        },\n      ],\n  }\n\n  A call to PlistValueFilter with context "items" and query "age > 25" will\n  return {\'name\': \'John\', \'age\': 33}.\n\n  If you don\'t specify a context, the full plist will be matched and returned\n  if the query succceeds. I,e: a call to PlistValueFilter without a context but\n  query "values contains 13" will return the full plist.\n\n\n  If you don\'t specify a query, all the values under the context parameter will\n  get returned. I.e: a call to PlistValueFilter with context "items.children"\n  and no query, will return [ [\'John\', \'Phil\'], []].\n  \n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="PlistValueFilter", request=request)\n\n  Args:\n    request\n      description: A request for the client to parse a plist file.\n      type: PlistRequest\n      default: None\n'
 name : u'PlistValueFilter'
}
<class 'abc.ProcessHuntResultCollectionsCronFlow'>
<class 'grr_response_server.flows.cron.system.PurgeClientStats'>
<class 'abc.RecursiveListDirectory'>
message ApiFlowDescriptor {
 args_type : u'RecursiveListDirectoryArgs'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'Filesystem'
 default_args :   <RecursiveListDirectoryArgs('message RecursiveListDirectoryArgs {\n}')>
 doc : u'Recursively list directory on the client.\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="RecursiveListDirectory", pathspec=pathspec, max_depth=max_depth)\n\n  Args:\n    max_depth\n      description: Maximum recursion depth.\n      type: RDFInteger\n      default: 5\n\n    pathspec\n      description: The pathspec for the directory to list.\n      type: PathSpec\n      default: None\n'
 name : u'RecursiveListDirectory'
}
<class 'abc.RegistryFinder'>
message ApiFlowDescriptor {
 args_type : u'RegistryFinderArgs'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Registry'
 default_args :   <RegistryFinderArgs(u'message RegistryFinderArgs {\n keys_paths : [\n   GlobExpression:\n     HKEY_USERS/%%users.sid%%/Softwa...')>
 doc : u'This flow looks for registry items matching given criteria.\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="RegistryFinder", keys_paths=keys_paths, conditions=conditions)\n\n  Args:\n    conditions\n      description: These conditions will be applied to all items that match the keys path arguments.\n      type: \n      default: None\n\n    keys_paths\n      description: Glob expression for registry keys to be retrieved.\n      type: \n      default: None\n'
 friendly_name : u'Registry Finder'
 name : u'RegistryFinder'
}
<class 'grr_response_server.hunts.standard.SampleHunt'>
<class 'abc.SendFile'>
message ApiFlowDescriptor {
 args_type : u'SendFileRequest'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'Filesystem'
 default_args :   <SendFileRequest('message SendFileRequest {\n}')>
 doc : u'This flow sends a file to remote listener.\n\n  To use this flow, choose a key and an IV in hex format (if run from the GUI,\n  there will be a pregenerated pair key and iv for you to use) and run a\n  listener on the server you want to use like this:\n\n  nc -l <port> | openssl aes-128-cbc -d -K <key> -iv <iv> > <filename>\n\n  Returns to parent flow:\n    A rdf_client_fs.StatEntry of the sent file.\n  \n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="SendFile", pathspec=pathspec, address_family=address_family, host=host, port=port, key=key, iv=iv)\n\n  Args:\n    address_family\n      description: address family to use (AF_INET or AF_INET6).\n      type: EnumNamedValue\n      default: INET\n\n    host\n      description: Hostname or IP to send the file to.\n      type: RDFString\n      default: \n\n    iv\n      description: The iv for AES, also given in hex representation.\n      type: AES128Key\n      default: None\n\n    key\n      description: An encryption key given in hex representation.\n      type: AES128Key\n      default: None\n\n    pathspec\n      description: The pathspec for the file to retrieve.\n      type: PathSpec\n      default: None\n\n    port\n      description: Port number on the listening server.\n      type: RDFInteger\n      default: 12345\n'
 name : u'SendFile'
}
<class 'abc.SystemRootSystemDriveFallbackFlow'>
<class 'grr_response_server.flows.general.transfer.TransferStore'>
<class 'abc.Uninstall'>
message ApiFlowDescriptor {
 args_type : u'UninstallArgs'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'Administrative'
 default_args :   <UninstallArgs('message UninstallArgs {\n}')>
 doc : u'Removes the persistence mechanism which the client uses at boot.\n\n  For Windows and OSX, this will disable the service, and then stop the service.\n  For Linux this flow will fail as we haven\'t implemented it yet :)\n  \n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="Uninstall", kill=kill)\n\n  Args:\n    kill\n      description: Kills the client if set.\n      type: RDFBool\n      default: 0\n'
 name : u'Uninstall'
}
<class 'abc.UpdateClient'>
message ApiFlowDescriptor {
 args_type : u'UpdateClientArgs'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'Administrative'
 default_args :   <UpdateClientArgs('message UpdateClientArgs {\n}')>
 doc : u'Updates the GRR client to a new version replacing the current client.\n\n  This will execute the specified installer on the client and then run\n  an Interrogate flow.\n\n  The new installer needs to be loaded into the database, generally in\n  /config/executables/<platform>/installers and must be signed using the\n  exec signing key.\n\n  Signing and upload of the file is done with config_updater.\n  \n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="UpdateClient", blob_path=blob_path)\n\n  Args:\n    blob_path\n      description: An aff4 path to a GRRSignedBlob of a new client version.\n      type: RDFURN\n      default: None\n'
 name : u'UpdateClient'
}
<class 'abc.UpdateConfiguration'>
<class 'abc.UpdateSparseImageChunks'>
message ApiFlowDescriptor {
 args_type : u'UpdateSparseImageChunksArgs'
 behaviours : [
   u'ADVANCED'
  ]
 category : u'Filesystem'
 default_args :   <UpdateSparseImageChunksArgs('message UpdateSparseImageChunksArgs {\n}')>
 doc : u'Updates a list of chunks of a sparse image from the client.\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="UpdateSparseImageChunks", file_urn=file_urn, chunks_to_fetch=chunks_to_fetch)\n\n  Args:\n    chunks_to_fetch\n      description: \n      type: \n      default: None\n\n    file_urn\n      description: The URN of the sparse image to update\n      type: RDFURN\n      default: None\n'
 name : u'UpdateSparseImageChunks'
}
<class 'grr_response_server.aff4_objects.aff4_grr.UpdateVFSFile'>
<class 'grr_response_server.hunts.standard.VariableGenericHunt'>
<class 'grr_response_server.flow.WellKnownFlow'>
<class 'abc.WindowsAllUsersProfileFallbackFlow'>
<class 'abc.YaraDumpProcessMemory'>
message ApiFlowDescriptor {
 args_type : u'YaraProcessDumpArgs'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Yara'
 default_args :   <YaraProcessDumpArgs('message YaraProcessDumpArgs {\n}')>
 doc : u'Acquires memory for a given list of processes.\n\n  Note that accessing process memory with Yara on Linux causes\n  processes to pause. This can impact the client machines when dumping\n  large processes.\n  \n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="YaraDumpProcessMemory", pids=pids, process_regex=process_regex, ignore_grr_process=ignore_grr_process, dump_all_processes=dump_all_processes, size_limit=size_limit, chunk_size=chunk_size, skip_special_regions=skip_special_regions, skip_mapped_files=skip_mapped_files, skip_shared_regions=skip_shared_regions, skip_executable_regions=skip_executable_regions, skip_readonly_regions=skip_readonly_regions)\n\n  Args:\n    chunk_size\n      description: The chunk size to use when reading large memory regions.\n      type: RDFInteger\n      default: 104857600\n\n    dump_all_processes\n      description: This dumps all processes. Might return lots of data, use with care.\n      type: RDFBool\n      default: 0\n\n    ignore_grr_process\n      description: By default, the GRR process is not dumped. Clear this flag to change this behavior.\n      type: RDFBool\n      default: 1\n\n    pids\n      description: A list of pids to dump.\n      type: \n      default: None\n\n    process_regex\n      description: A regex to match against the process name. Only matching names will be dumped.\n      type: RDFString\n      default: \n\n    size_limit\n      description: Maximum amount of raw process memory to dump. Applies to all requested processes together. The first memory block going over the limit will not be written anymore. 0 indicates no limit.\n      type: ByteSize\n      default: 0\n\n    skip_executable_regions\n      description: Set this flag to avoid dumping executable regions. Applies to Linux and macOS.\n      type: RDFBool\n      default: 0\n\n    skip_mapped_files\n      description: Set this flag to avoid dumping mapped files. Applies to Linux only.\n      type: RDFBool\n      default: 1\n\n    skip_readonly_regions\n      description: Set this flag to avoid dumping readonly regions. Applies to Linux and macOS.\n      type: RDFBool\n      default: 0\n\n    skip_shared_regions\n      description: Set this flag to avoid dumping shared regions. Applies to Linux and macOS.\n      type: RDFBool\n      default: 0\n\n    skip_special_regions\n      description: Set this flag to avoid dumping device backed regions and guard pages. Applies to Windows only.\n      type: RDFBool\n      default: 0\n'
 friendly_name : u'Yara Process Dump'
 name : u'YaraDumpProcessMemory'
}
<class 'abc.YaraProcessScan'>
message ApiFlowDescriptor {
 args_type : u'YaraProcessScanRequest'
 behaviours : [
   u'ADVANCED'
   u'BASIC'
  ]
 category : u'Yara'
 default_args :   <YaraProcessScanRequest('message YaraProcessScanRequest {\n}')>
 doc : u'Scans process memory using Yara.\n\n  Call Spec:\n    flow.StartAFF4Flow(client_id=client_id, flow_name="YaraProcessScan", yara_signature=yara_signature, pids=pids, process_regex=process_regex, include_errors_in_results=include_errors_in_results, include_misses_in_results=include_misses_in_results, ignore_grr_process=ignore_grr_process, per_process_timeout=per_process_timeout, chunk_size=chunk_size, overlap_size=overlap_size, skip_special_regions=skip_special_regions, skip_mapped_files=skip_mapped_files, skip_shared_regions=skip_shared_regions, skip_executable_regions=skip_executable_regions, skip_readonly_regions=skip_readonly_regions, dump_process_on_match=dump_process_on_match, max_results_per_process=max_results_per_process)\n\n  Args:\n    chunk_size\n      description: The chunk size to use when scanning large memory regions.\n      type: RDFInteger\n      default: 104857600\n\n    dump_process_on_match\n      description: Set this flag to schedule a process memory dump on every signature match.\n      type: RDFBool\n      default: 0\n\n    ignore_grr_process\n      description: By default, the GRR process is not scanned. Clear this flag to change this behavior.\n      type: RDFBool\n      default: 1\n\n    include_errors_in_results\n      description: Include processes that we failed to scan into returned results.\n      type: RDFBool\n      default: 0\n\n    include_misses_in_results\n      description: Include processes that came back without matches into returned results.\n      type: RDFBool\n      default: 0\n\n    max_results_per_process\n      description: Set this to limit the number of matches returned for each process scanned.\n      type: RDFInteger\n      default: 0\n\n    overlap_size\n      description: The overlap size to use when scanning large memory regions.\n      type: RDFInteger\n      default: 10485760\n\n    per_process_timeout\n      description: A timeout in seconds that is applied while scanning; applies to each scan individually.\n      type: RDFInteger\n      default: 0\n\n    pids\n      description: The pids to scan. No pids given indicates all processes.\n      type: \n      default: None\n\n    process_regex\n      description: A regex to match against the process name. Only matching names will be scanned.\n      type: RDFString\n      default: \n\n    skip_executable_regions\n      description: Set this flag to avoid scanning executable regions. Applies to Linux and macOS.\n      type: RDFBool\n      default: 0\n\n    skip_mapped_files\n      description: Set this flag to avoid scanning mapped files. Applies to Linux only.\n      type: RDFBool\n      default: 1\n\n    skip_readonly_regions\n      description: Set this flag to avoid scanning readonly regions. Applies to Linux and macOS.\n      type: RDFBool\n      default: 0\n\n    skip_shared_regions\n      description: Set this flag to avoid scanning shared regions. Applies to Linux and macOS.\n      type: RDFBool\n      default: 0\n\n    skip_special_regions\n      description: Set this flag to avoid scanning device backed regions and guard pages. Applies to Windows only.\n      type: RDFBool\n      default: 0\n\n    yara_signature\n      description: The yara signature(s) to use for scanning.\n      type: YaraSignature\n      default: None\n'
 friendly_name : u'Yara Process Scan'
 name : u'YaraProcessScan'

53. navigator.html: u can change or add anything related to creating flows or any new button w keda

54. This is where flow details gets initiated: [the right side of strat flows page"
<div grr-splitter orientation="horizontal" class="flow-details">

    <div grr-splitter-pane size="75" id="main_rightTopPane" class="rightTopPane">
      <grr-start-flow-form client-id="controller.clientId"
                           descriptor="controller.selection.flowDescriptor" />
    </div>

    <div grr-splitter-pane size="25" id="main_rightBottomPane" class="rightBottomPane">
      <grr-flow-info descriptor="controller.selection.flowDescriptor" />
    </div>

  </div>

55. also look at grr-start-flow-form for each part in the conetxt:
it knows all flow args and runner args from the descriptor which already got them when initializing:
<grr-flow-form flow-args="controller.flowArguments"
                 flow-runner-args="controller.flowRunnerArguments"
                 with-output-plugins="clientId"
                 has-errors="controller.flowFormHasErrors">
  </grr-flow-form>

56. This is how data is fetched from ui and sent into wsgi.py: [in start_flow_directive.js]
  this.grrApiService_.post('/clients/' + clientId + '/flows', {
    flow: {
      runner_args: stripTypeInfo(this.flowRunnerArguments),
      args: stripTypeInfo(this.flowArguments)
    }
  }).then(function success(response) {
    this.responseData = response['data'];
  }.bind(this), function failure(response) {
    this.responseError = response['data']['message'] || 'Unknown error';
  }.bind(this));
  this.requestSent = true;
};

57. New Style Flows:
FlowBase
KnowledgeBaseInitializationFlow
SystemRootSystemDriveFallbackFlow
WindowsAllUsersProfileFallbackFlow
GetFile
MultiGetFile
GetMBR
SendFile
ListDirectory
RecursiveListDirectory
UpdateSparseImageChunks
FetchBufferForSparseImage
Glob
DiskVolumeInfo
FingerprintFile
FileFinder
ClientFileFinder
ArtifactCollectorFlow
ArtifactFilesDownloaderFlow
ClientArtifactCollector
Interrogate
GetClientStats
DeleteGRRTempFiles
Uninstall
Kill
UpdateConfiguration
ExecutePythonHack
ExecuteCommand
OnlineNotification
UpdateClient
KeepAlive
LaunchBinary
CAEnroler
CheckRunner
FindFiles
DumpFlashImage
DumpACPITable
Netstat
OsqueryFlow
ListProcesses
RegistryFinder
CollectRunKeyBinaries
ChromeHistory
FirefoxHistory
CacheGrep
YaraProcessScan
YaraDumpProcessMemory


58. flows of aff4flowregistery:
FlowBase
GRRFlow
WellKnownFlow
UpdateVFSFile
KnowledgeBaseInitializationFlow
SystemRootSystemDriveFallbackFlow
WindowsAllUsersProfileFallbackFlow
GetFile
MultiGetFile
GetMBR
TransferStore
SendFile
ListDirectory
RecursiveListDirectory
UpdateSparseImageChunks
FetchBufferForSparseImage
MakeNewAFF4SparseImage
Glob
DiskVolumeInfo
FingerprintFile
FileFinder
ClientFileFinder
ArtifactCollectorFlow
ArtifactFilesDownloaderFlow
ClientArtifactCollector
SystemCronFlow
StatefulSystemCronFlow
GRRHunt
CleanHunts
CleanCronJobs
CleanInactiveClients
Interrogate
CreateGenericHuntFlow
CreateAndRunGenericHuntFlow
SampleHunt
GenericHunt
VariableGenericHunt
AbstractClientStatsCronFlow
GRRVersionBreakDown
OSBreakDown
LastAccessStats
InterrogateClientsCronFlow
PurgeClientStats
GetClientStats
GetClientStatsAuto
DeleteGRRTempFiles
Uninstall
Kill
UpdateConfiguration
ExecutePythonHack
ExecuteCommand
Foreman
OnlineNotification
UpdateClient
NannyMessageHandlerFlow
ClientAlertHandlerFlow
ClientStartupHandlerFlow
KeepAlive
LaunchBinary
CAEnroler
Enroler
CheckRunner
ClientVfsMigrationFlow
PlistValueFilter
FindFiles
DumpFlashImage
DumpACPITable
Netstat
OsqueryFlow
ListProcesses
RegistryFinder
CollectRunKeyBinaries
ChromeHistory
FirefoxHistory
CacheGrep
ListVolumeShadowCopies
YaraProcessScan
YaraDumpProcessMemory
ProcessHuntResultCollectionsCronFlow

59. worth looking at later on: 
class EventRegistry(MetaclassRegistry)

60. where the registery gets initiated:
  File "/home/samanoudy/.virtualenv/GRR/bin/grr_admin_ui", line 11, in <module>
    load_entry_point('grr-response-server', 'console_scripts', 'grr_admin_ui')()
  File "/home/samanoudy/grr/grr/server/grr_response_server/distro_entry.py", line 48, in AdminUI
    from grr_response_server.gui import admin_ui
  File "/home/samanoudy/grr/grr/server/grr_response_server/gui/admin_ui.py", line 24, in <module>
    from grr_response_server import server_plugins
  File "/home/samanoudy/grr/grr/server/grr_response_server/server_plugins.py", line 18, in <module>
    from grr_response_server import export
  File "/home/samanoudy/grr/grr/server/grr_response_server/export.py", line 34, in <module>
    from grr_response_server import aff4
  File "/home/samanoudy/grr/grr/server/grr_response_server/aff4.py", line 41, in <module>
    from grr_response_server import data_store
  File "/home/samanoudy/grr/grr/server/grr_response_server/data_store.py", line 70, in <module>
    from grr_response_server import db
  File "/home/samanoudy/grr/grr/server/grr_response_server/db.py", line 45, in <module>
    from grr_response_server.rdfvalues import hunt_objects as rdf_hunt_objects	
  File "/home/samanoudy/grr/grr/server/grr_response_server/rdfvalues/hunt_objects.py", line 64, in <module>
    class Hunt(rdf_structs.RDFProtoStruct):
  File "/home/samanoudy/grr/grr/core/grr_response_core/lib/rdfvalues/structs.py", line 1633, in __init__
    rdf_proto2.DefineFromProtobuf(cls, cls.protobuf)
  File "/home/samanoudy/grr/grr/core/grr_response_core/lib/rdfvalues/proto2.py", line 211, in DefineFromProtobuf
    field.message_type.name))

61. using rdfstruct protos is mainly for the following reasons:
 """An RDFStruct which uses protobufs for serialization.
  This implementation is faster than the standard protobuf library.
  """
62. there u could have any rdf deps to know any rdf values used by such proto as well. [such rdf values are usually also inherited from rdfstruct protos]
https://afs.github.io/rdf-thrift/rdf-binary-thrift.html

63. an aff4 object may contain an rdf value as one of its schema attributes. An rdf value may be non-part of any aff4 object as well. An Rdf value may be using Protopufs for serialization. Protopufs can be used for effecient data transfer while rdf is used for encoding and decoding for human readable formats.

64. take a deeper look at flow_responses fakeresponse class:
An object which emulates the responses.
  This is only used internally to call a state method inline.

65. How did they create the SignedBlob datatype and referenced it in the protopufs anywayss???
66. no idea what is this: api_call_robot_router

67. workers may work for specified queus for work in queues class defined in response_core_lib; needs deeper look
68. flow_runner is responsible for the stuff with queue manager and creating urn for flows from session id, specifyin qued replies and requests

69. Note that    # While wrapping the response in GrrMessage is not strictly necessary for
      # output plugins, GrrMessage.source may be used by these plugins to fetch
      # client's metadata and include it into the exported data.

70. look at this later on:
ERROR:2019-03-16 22:31:41,973 9409 MainProcess 139948654995200 Thread-193 frontend:205] Had to respond with status 500.
Traceback (most recent call last):
  File "/home/samanoudy/grr/grr/server/grr_response_server/bin/frontend.py", line 199, in do_POST
    self.Control()
  File "/home/samanoudy/grr/grr/core/grr_response_core/stats/stats_utils.py", line 55, in Decorated
    return func(*args, **kwargs)
  File "/home/samanoudy/grr/grr/core/grr_response_core/stats/stats_utils.py", line 33, in Decorated
    return func(*args, **kwargs)
  File "/home/samanoudy/grr/grr/server/grr_response_server/bin/frontend.py", line 261, in Control
    request_comms, responses_comms)
  File "/home/samanoudy/grr/grr/core/grr_response_core/stats/stats_utils.py", line 55, in Decorated
    return func(*args, **kwargs)
  File "/home/samanoudy/grr/grr/core/grr_response_core/stats/stats_utils.py", line 33, in Decorated
    return func(*args, **kwargs)
  File "/home/samanoudy/grr/grr/server/grr_response_server/frontend_lib.py", line 400, in HandleMessageBundles
    self.ReceiveMessages(source, messages)
  File "/home/samanoudy/grr/grr/server/grr_response_server/frontend_lib.py", line 676, in ReceiveMessages
    "ClientCrash", crash_details, token=self.token)
  File "/home/samanoudy/grr/grr/server/grr_response_server/events.py", line 51, in PublishEvent
    cls.PublishMultipleEvents({event_name: [msg]}, token=token)
  File "/home/samanoudy/grr/grr/server/grr_response_server/events.py", line 76, in PublishMultipleEvents
    event_cls().ProcessMessages(messages, token=token)
  File "/home/samanoudy/grr/grr/server/grr_response_server/flows/general/administrative.py", line 215, in ProcessMessages
    is_html=True)
  File "/home/samanoudy/grr/grr/server/grr_response_server/email_alerts.py", line 153, in SendEmail
    (config.CONFIG["Worker.smtp_server"], e))
RuntimeError: Could not connect to SMTP server to send email. Please check config option Worker.smtp_server. Currently set to localhost. Error: [Errno 111] Connection refused
ERROR:2019-03-16 22:32:42,468 9409 MainProcess 139948654995200 Thread-194 frontend:205] Had to respond with status 500.
Traceback (most recent call last):
  File "/home/samanoudy/grr/grr/server/grr_response_server/bin/frontend.py", line 199, in do_POST
    self.Control()
  File "/home/samanoudy/grr/grr/core/grr_response_core/stats/stats_utils.py", line 55, in Decorated
    return func(*args, **kwargs)
  File "/home/samanoudy/grr/grr/core/grr_response_core/stats/stats_utils.py", line 33, in Decorated
    return func(*args, **kwargs)
  File "/home/samanoudy/grr/grr/server/grr_response_server/bin/frontend.py", line 261, in Control
    request_comms, responses_comms)
  File "/home/samanoudy/grr/grr/core/grr_response_core/stats/stats_utils.py", line 55, in Decorated
    return func(*args, **kwargs)
  File "/home/samanoudy/grr/grr/core/grr_response_core/stats/stats_utils.py", line 33, in Decorated
    return func(*args, **kwargs)
  File "/home/samanoudy/grr/grr/server/grr_response_server/frontend_lib.py", line 400, in HandleMessageBundles
    self.ReceiveMessages(source, messages)
  File "/home/samanoudy/grr/grr/server/grr_response_server/frontend_lib.py", line 676, in ReceiveMessages
    "ClientCrash", crash_details, token=self.token)
  File "/home/samanoudy/grr/grr/server/grr_response_server/events.py", line 51, in PublishEvent
    cls.PublishMultipleEvents({event_name: [msg]}, token=token)
  File "/home/samanoudy/grr/grr/server/grr_response_server/events.py", line 76, in PublishMultipleEvents
    event_cls().ProcessMessages(messages, token=token)
  File "/home/samanoudy/grr/grr/server/grr_response_server/flows/general/administrative.py", line 215, in ProcessMessages
    is_html=True)
  File "/home/samanoudy/grr/grr/server/grr_response_server/email_alerts.py", line 153, in SendEmail
    (config.CONFIG["Worker.smtp_server"], e))
RuntimeError: Could not connect to SMTP server to send email. Please check config option Worker.smtp_server. Currently set to localhost. Error: [Errno 111] Connection refused


71. check more on the Uninstall flow: what is the original flow?
72. This error appears when trying to execute ping commands on client:
GENERIC_ERROR
Error message 	OSError(2, 'No such file or directory'): [Errno 2] No such file or directory
Backtrace 	Traceback (most recent call last): File "/home/samanoudy/grr/grr/client/grr_response_client/actions.py", line 146, in Execute self.Run(args) File "/home/samanoudy/grr/grr/client/grr_response_client/client_actions/standard.py", line 660, in Run for res in ExecuteLineFromClient(args): File "/home/samanoudy/grr/grr/client/grr_response_client/client_actions/standard.py", line 637, in ExecuteLineFromClient res = client_utils_common.ExecuteLine(cmd, time_limit) File "/home/samanoudy/grr/grr/client/grr_response_client/client_utils_common.py", line 321, in ExecuteLine cmd,time_limit, use_client_context=use_client_context, cwd=cwd) File "/home/samanoudy/grr/grr/client/grr_response_client/client_utils_common.py", line 342, in _ExecuteLine cwd=cwd) File "/usr/lib/python2.7/subprocess.py", line 394, in __init__ errread, errwrite) File "/usr/lib/python2.7/subprocess.py", line 1047, in _execute_child raise child_exception OSError: [Errno 2] No such file or directory
Cpu time used 	
User cpu seconds used 	0
System cpu seconds used 	0

__%EOF%__

__%BOF%__
1. need to look at grr_client components.actions. grr_chipsec for more info
2. ac and gui folders are the only change from master base and Nofal's
3. Great Issue Solves for TK error:
https://stackoverflow.com/questions/15884075/tkinter-in-a-virtualenv
4. requirments.txt include the orginal but pointing to Nofal's master
5. requirements2.txt has the google's master and need to pip/install all in the new cloned dir
6. check https://github.com/google/grr/tree/master/terraform/demo/google
and https://github.com/google/grr/issues/672
for db instances	
7. pip uninstall grr-response-server then redownload it again (3.2.4post6 is the currently working not post9!)
8. also check https://github.com/google/grr/issues/639 for db 
9. Checking write access on config /home/samanoudy/grr_new/grr/core/install_data/etc/server.local.yaml
10. check response_server/mysql_pool for the "connectionpool" in the database
11. response_core/lib/communicator includes the DecodeMessages func: inside it all messages get verified and message list could be seen 
12. after that it goes to VerifyMessageSignature [in server/frontend_lib] to check the signature
13. EncodeMessages in communicator in response core is used by the client and also the server.
14. Web of Trust vs PKI.
15. used AES: 128 cbc with iv and nonce is timestamp;
	integ: use simple hmac or full hmac depending on endpoint compatibility
16. #TODO isa: 
		I. See why the executeline returns the output in status instead of results
		II. Dig deeper in the databases dir in server
		III.  Dig deeper in the CA_enroller flow and applied crypto
__%EOF%__
