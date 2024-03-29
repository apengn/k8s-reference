# kube-apiserver
### 简介
The Kubernetes API server validates and configures data for the api objects which include pods, services, replicationcontrollers, and others. The API Server services REST operations and provides the frontend to the cluster’s shared state through which all other components interact.

`kube-apiserver [flags]`
### 选项

| ID | 参数 |说明 |
| :-:| :---------- | :---------- |
|1|--admission-control-config-file string|File with admission control configuration.|
|2|--advertise-address ip|The IP address on which to advertise the apiserver to members of the cluster. This address must be reachable by the rest of the cluster. If blank, the --bind-address will be used. If --bind-address is unspecified, the host's default interface will be used.|
|3|--allow-privileged|If true, allow privileged containers. [default=false]|
|4|--alsologtostderr|log to standard error as well as files|
|5|--anonymous-auth     Default: true|Enables anonymous requests to the secure port of the API server. Requests that are not rejected by another authentication method are treated as anonymous requests. Anonymous requests have a username of system:anonymous, and a group name of system:unauthenticated.|
|6|--api-audiences stringSlice|Identifiers of the API. The service account token authenticator will validate that tokens used against the API are bound to at least one of these audiences. If the --service-account-issuer flag is configured and this flag is not, this field defaults to a single element list containing the issuer URL .|
|7|--apiserver-count int     Default: 1|The number of apiservers running in the cluster, must be a positive number. (In use when --endpoint-reconciler-type=master-count is enabled.)|
|8|--audit-dynamic-configuration|Enables dynamic audit configuration. This feature also requires the DynamicAuditing feature flag|
|9|--audit-log-batch-buffer-size int     Default: 10000|The size of the buffer to store events before batching and writing. Only used in batch mode.|
|10|--audit-log-batch-max-size int     Default: 1|The maximum size of a batch. Only used in batch mode.|
|11|--audit-log-batch-max-wait duration|The amount of time to wait before force writing the batch that hadn't reached the max size. Only used in batch mode.|
|12|--audit-log-batch-throttle-burst int|Maximum number of requests sent at the same moment if ThrottleQPS was not utilized before. Only used in batch mode.|
|13|--audit-log-batch-throttle-enable|Whether batching throttling is enabled. Only used in batch mode.|
|14|--audit-log-batch-throttle-qps float32|Maximum average number of batches per second. Only used in batch mode.|
|15|--audit-log-format string     Default: "json"|Format of saved audits. "legacy" indicates 1-line text format for each event. "json" indicates structured json format. Known formats are legacy,json.|
|16|--audit-log-maxage int|The maximum number of days to retain old audit log files based on the timestamp encoded in their filename.|
|17|--audit-log-maxbackup int|The maximum number of old audit log files to retain.|
|18|--audit-log-maxsize int|The maximum size in megabytes of the audit log file before it gets rotated.|
|19|--audit-log-mode string     Default: "blocking"|Strategy for sending audit events. Blocking indicates sending events should block server responses. Batch causes the backend to buffer and write events asynchronously. Known modes are batch,blocking,blocking-strict.|
|20|--audit-log-path string|If set, all requests coming to the apiserver will be logged to this file. '-' means standard out.|
|21|--audit-log-truncate-enabled|Whether event and batch truncating is enabled.|
|22|--audit-log-truncate-max-batch-size int     Default: 10485760|Maximum size of the batch sent to the underlying backend. Actual serialized size can be several hundreds of bytes greater. If a batch exceeds this limit, it is split into several batches of smaller size.|
|23|--audit-log-truncate-max-event-size int     Default: 102400|Maximum size of the audit event sent to the underlying backend. If the size of an event is greater than this number, first request and response are removed, and if this doesn't reduce the size enough, event is discarded.|
|24|--audit-log-version string     Default: "audit.k8s.io/v1"|API group and version used for serializing audit events written to log.|
|25|--audit-policy-file string|Path to the file that defines the audit policy configuration.|
|26|--audit-webhook-batch-buffer-size int     Default: 10000|The size of the buffer to store events before batching and writing. Only used in batch mode.|
|27|--audit-webhook-batch-max-size int     Default: 400|The maximum size of a batch. Only used in batch mode.|
|28|--audit-webhook-batch-max-wait duration     Default: 30s|The amount of time to wait before force writing the batch that hadn't reached the max size. Only used in batch mode.|
|29|--audit-webhook-batch-throttle-burst int     Default: 15|Maximum number of requests sent at the same moment if ThrottleQPS was not utilized before. Only used in batch mode.|
|30|--audit-webhook-batch-throttle-enable     Default: true|Whether batching throttling is enabled. Only used in batch mode.|
|31|--audit-webhook-batch-throttle-qps float32     Default: 10|Maximum average number of batches per second. Only used in batch mode.|
|32|--audit-webhook-config-file string|Path to a kubeconfig formatted file that defines the audit webhook configuration.|
|33|--audit-webhook-initial-backoff duration     Default: 10s|The amount of time to wait before retrying the first failed request.|
|34|--audit-webhook-mode string     Default: "batch"|Strategy for sending audit events. Blocking indicates sending events should block server responses. Batch causes the backend to buffer and write events asynchronously. Known modes are batch,blocking,blocking-strict.|
|35|--audit-webhook-truncate-enabled|Whether event and batch truncating is enabled.|
|36|--audit-webhook-truncate-max-batch-size int     Default: 10485760|Maximum size of the batch sent to the underlying backend. Actual serialized size can be several hundreds of bytes greater. If a batch exceeds this limit, it is split into several batches of smaller size.|
|37|--audit-webhook-truncate-max-event-size int     Default: 102400|Maximum size of the audit event sent to the underlying backend. If the size of an event is greater than this number, first request and response are removed, and if this doesn't reduce the size enough, event is discarded.|
|38|--audit-webhook-version string     Default: "audit.k8s.io/v1"|API group and version used for serializing audit events written to webhook.|
|39|--authentication-token-webhook-cache-ttl duration     Default: 2m0s|The duration to cache responses from the webhook token authenticator.|
|40|--authentication-token-webhook-config-file string|File with webhook configuration for token authentication in kubeconfig format. The API server will query the remote service to determine authentication for bearer tokens.|
|41|--authorization-mode stringSlice     Default: [AlwaysAllow]|Ordered list of plug-ins to do authorization on secure port. Comma-delimited list of: AlwaysAllow,AlwaysDeny,ABAC,Webhook,RBAC,Node.|
|42|--authorization-policy-file string|File with authorization policy in json line by line format, used with --authorization-mode=ABAC, on the secure port.|
|43|--authorization-webhook-cache-authorized-ttl duration     Default: 5m0s|The duration to cache 'authorized' responses from the webhook authorizer.|
|44|--authorization-webhook-cache-unauthorized-ttl duration     Default: 30s|The duration to cache 'unauthorized' responses from the webhook authorizer.|
|45|--authorization-webhook-config-file string|File with webhook configuration in kubeconfig format, used with --authorization-mode=Webhook. The API server will query the remote service to determine access on the API server's secure port.|
|46|--azure-container-registry-config string|Path to the file containing Azure container registry configuration information.|
|47|--basic-auth-file string|If set, the file that will be used to admit requests to the secure port of the API server via http basic authentication.|
|48|--bind-address ip     Default: 0.0.0.0|The IP address on which to listen for the --secure-port port. The associated interface(s) must be reachable by the rest of the cluster, and by CLI/web clients. If blank, all interfaces will be used (0.0.0.0 for all IPv4 interfaces and :: for all IPv6 interfaces).|
|49|--cert-dir string     Default: "/var/run/kubernetes"|The directory where the TLS certs are located. If --tls-cert-file and --tls-private-key-file are provided, this flag will be ignored.|
|50|--client-ca-file string|If set, any request presenting a client certificate signed by one of the authorities in the client-ca-file is authenticated with an identity corresponding to the CommonName of the client certificate.|
|51|--cloud-config string|The path to the cloud provider configuration file. Empty string for no configuration file.|
|52|--cloud-provider string|The provider for cloud services. Empty string for no provider.|
|53|--cloud-provider-gce-lb-src-cidrs cidrs     Default: 130.211.0.0/22,209.85.152.0/22,209.85.204.0/22,35.191.0.0/16|CIDRs opened in GCE firewall for LB traffic proxy & health checks|
|54|--contention-profiling|Enable lock contention profiling, if profiling is enabled|
|55|--cors-allowed-origins stringSlice|List of allowed origins for CORS, comma separated. An allowed origin can be a regular expression to support subdomain matching. If this list is empty CORS will not be enabled.|
|56|--default-not-ready-toleration-seconds int     Default: 300|Indicates the tolerationSeconds of the toleration for notReady:NoExecute that is added by default to every pod that does not already have such a toleration.|
|57|--default-unreachable-toleration-seconds int     Default: 300|Indicates the tolerationSeconds of the toleration for unreachable:NoExecute that is added by default to every pod that does not already have such a toleration.|
|58|--default-watch-cache-size int     Default: 100|Default watch cache size. If zero, watch cache will be disabled for resources that do not have a default watch size set.|
|59|--delete-collection-workers int     Default: 1|Number of workers spawned for DeleteCollection call. These are used to speed up namespace cleanup.|
|60|--disable-admission-plugins stringSlice|admission plugins that should be disabled although they are in the default enabled plugins list (NamespaceLifecycle, LimitRanger, ServiceAccount, TaintNodesByCondition, Priority, DefaultTolerationSeconds, DefaultStorageClass, PersistentVolumeClaimResize, MutatingAdmissionWebhook, ValidatingAdmissionWebhook, ResourceQuota). Comma-delimited list of admission plugins: AlwaysAdmit, AlwaysDeny, AlwaysPullImages, DefaultStorageClass, DefaultTolerationSeconds, DenyEscalatingExec, DenyExecOnPrivileged, EventRateLimit, ExtendedResourceToleration, ImagePolicyWebhook, LimitPodHardAntiAffinityTopology, LimitRanger, MutatingAdmissionWebhook, NamespaceAutoProvision, NamespaceExists, NamespaceLifecycle, NodeRestriction, OwnerReferencesPermissionEnforcement, PersistentVolumeClaimResize, PersistentVolumeLabel, PodNodeSelector, PodPreset, PodSecurityPolicy, PodTolerationRestriction, Priority, ResourceQuota, SecurityContextDeny, ServiceAccount, StorageObjectInUseProtection, TaintNodesByCondition, ValidatingAdmissionWebhook. The order of plugins in this flag does not matter.|
|61|--enable-admission-plugins stringSlice|admission plugins that should be enabled in addition to default enabled ones (NamespaceLifecycle, LimitRanger, ServiceAccount, TaintNodesByCondition, Priority, DefaultTolerationSeconds, DefaultStorageClass, PersistentVolumeClaimResize, MutatingAdmissionWebhook, ValidatingAdmissionWebhook, ResourceQuota). Comma-delimited list of admission plugins: AlwaysAdmit, AlwaysDeny, AlwaysPullImages, DefaultStorageClass, DefaultTolerationSeconds, DenyEscalatingExec, DenyExecOnPrivileged, EventRateLimit, ExtendedResourceToleration, ImagePolicyWebhook, LimitPodHardAntiAffinityTopology, LimitRanger, MutatingAdmissionWebhook, NamespaceAutoProvision, NamespaceExists, NamespaceLifecycle, NodeRestriction, OwnerReferencesPermissionEnforcement, PersistentVolumeClaimResize, PersistentVolumeLabel, PodNodeSelector, PodPreset, PodSecurityPolicy, PodTolerationRestriction, Priority, ResourceQuota, SecurityContextDeny, ServiceAccount, StorageObjectInUseProtection, TaintNodesByCondition, ValidatingAdmissionWebhook. The order of plugins in this flag does not matter.|
|62|--enable-aggregator-routing|Turns on aggregator routing requests to endpoints IP rather than cluster IP.|
|63|--enable-bootstrap-token-auth|Enable to allow secrets of type 'bootstrap.kubernetes.io/token' in the 'kube-system' namespace to be used for TLS bootstrapping authentication.|
|64|--enable-garbage-collector     Default: true|Enables the generic garbage collector. MUST be synced with the corresponding flag of the kube-controller-manager.|
|65|--enable-logs-handler     Default: true|If true, install a /logs handler for the apiserver logs.|
|66|--encryption-provider-config string|The file containing configuration for encryption providers to be used for storing secrets in etcd|
|67|--endpoint-reconciler-type string     Default: "lease"|Use an endpoint reconciler (master-count, lease, none)|
|68|--etcd-cafile string|SSL Certificate Authority file used to secure etcd communication.|
|69|--etcd-certfile string|SSL certification file used to secure etcd communication.|
|70|--etcd-compaction-interval duration     Default: 5m0s|The interval of compaction requests. If 0, the compaction request from apiserver is disabled.|
|71|--etcd-count-metric-poll-period duration     Default: 1m0s|Frequency of polling etcd for number of resources per type. 0 disables the metric collection.|
|72|--etcd-keyfile string|SSL key file used to secure etcd communication.|
|73|--etcd-prefix string     Default: "/registry"|The prefix to prepend to all resource paths in etcd.|
|74|--etcd-servers stringSlice|List of etcd servers to connect with (scheme://ip:port), comma separated.|
|75|--etcd-servers-overrides stringSlice|Per-resource etcd servers overrides, comma separated. The individual override format: group/resource#servers, where servers are URLs, semicolon separated.|
|76|--event-ttl duration     Default: 1h0m0s|Amount of time to retain events.|
|77|--external-hostname string|The hostname to use when generating externalized URLs for this master (e.g. Swagger API Docs).|
|78|--feature-gates mapStringBool|A set of key=value pairs that describe feature gates for alpha/experimental features. Options are:|
|79||APIListChunking=true|false (BETA - default=true)|
|80||APIResponseCompression=true|false (ALPHA - default=false)|
|81||AllAlpha=true|false (ALPHA - default=false)|
|82||AppArmor=true|false (BETA - default=true)|
|83||AttachVolumeLimit=true|false (BETA - default=true)|
|84||BalanceAttachedNodeVolumes=true|false (ALPHA - default=false)|
|85||BlockVolume=true|false (BETA - default=true)|
|86||BoundServiceAccountTokenVolume=true|false (ALPHA - default=false)|
|87||CPUManager=true|false (BETA - default=true)|
|88||CRIContainerLogRotation=true|false (BETA - default=true)|
|89||CSIBlockVolume=true|false (BETA - default=true)|
|90||CSIDriverRegistry=true|false (BETA - default=true)|
|91||CSIInlineVolume=true|false (ALPHA - default=false)|
|92||CSIMigration=true|false (ALPHA - default=false)|
|93||CSIMigrationAWS=true|false (ALPHA - default=false)|
|94||CSIMigrationGCE=true|false (ALPHA - default=false)|
|95||CSIMigrationOpenStack=true|false (ALPHA - default=false)|
|96||CSINodeInfo=true|false (BETA - default=true)|
|97||CustomCPUCFSQuotaPeriod=true|false (ALPHA - default=false)|
|98||CustomResourcePublishOpenAPI=true|false (ALPHA - default=false)|
|99||CustomResourceSubresources=true|false (BETA - default=true)|
|100||CustomResourceValidation=true|false (BETA - default=true)|
|101||CustomResourceWebhookConversion=true|false (ALPHA - default=false)|
|102||DebugContainers=true|false (ALPHA - default=false)|
|103||DevicePlugins=true|false (BETA - default=true)|
|104||DryRun=true|false (BETA - default=true)|
|105||DynamicAuditing=true|false (ALPHA - default=false)|
|106||DynamicKubeletConfig=true|false (BETA - default=true)|
|107||ExpandCSIVolumes=true|false (ALPHA - default=false)|
|108||ExpandInUsePersistentVolumes=true|false (ALPHA - default=false)|
|109||ExpandPersistentVolumes=true|false (BETA - default=true)|
|110||ExperimentalCriticalPodAnnotation=true|false (ALPHA - default=false)|
|111||ExperimentalHostUserNamespaceDefaulting=true|false (BETA - default=false)|
|112||HyperVContainer=true|false (ALPHA - default=false)|
|113||KubeletPodResources=true|false (ALPHA - default=false)|
|114||LocalStorageCapacityIsolation=true|false (BETA - default=true)|
|115||MountContainers=true|false (ALPHA - default=false)|
|116||NodeLease=true|false (BETA - default=true)|
|117||PodShareProcessNamespace=true|false (BETA - default=true)|
|118||ProcMountType=true|false (ALPHA - default=false)|
|119||QOSReserved=true|false (ALPHA - default=false)|
|120||ResourceLimitsPriorityFunction=true|false (ALPHA - default=false)|
|121||ResourceQuotaScopeSelectors=true|false (BETA - default=true)|
|122||RotateKubeletClientCertificate=true|false (BETA - default=true)|
|123||RotateKubeletServerCertificate=true|false (BETA - default=true)|
|124||RunAsGroup=true|false (BETA - default=true)|
|125||RuntimeClass=true|false (BETA - default=true)|
|126||SCTPSupport=true|false (ALPHA - default=false)|
|127||ScheduleDaemonSetPods=true|false (BETA - default=true)|
|128||ServerSideApply=true|false (ALPHA - default=false)|
|129||ServiceNodeExclusion=true|false (ALPHA - default=false)|
|130||StorageVersionHash=true|false (ALPHA - default=false)|
|131||StreamingProxyRedirects=true|false (BETA - default=true)|
|132||SupportNodePidsLimit=true|false (ALPHA - default=false)|
|133||SupportPodPidsLimit=true|false (BETA - default=true)|
|134||Sysctls=true|false (BETA - default=true)|
|135||TTLAfterFinished=true|false (ALPHA - default=false)|
|136||TaintBasedEvictions=true|false (BETA - default=true)|
|137||TaintNodesByCondition=true|false (BETA - default=true)|
|138||TokenRequest=true|false (BETA - default=true)|
|139||TokenRequestProjection=true|false (BETA - default=true)|
|140||ValidateProxyRedirects=true|false (BETA - default=true)|
|141||VolumeSnapshotDataSource=true|false (ALPHA - default=false)|
|142||VolumeSubpathEnvExpansion=true|false (ALPHA - default=false)|
|143||WinDSR=true|false (ALPHA - default=false)|
|144||WinOverlay=true|false (ALPHA - default=false)|
|145||WindowsGMSA=true|false (ALPHA - default=false)|
|146|-h, --help|help for kube-apiserver|
|147|--http2-max-streams-per-connection int|The limit that the server gives to clients for the maximum number of streams in an HTTP/2 connection. Zero means to use golang's default.|
|148|--kubelet-certificate-authority string|Path to a cert file for the certificate authority.|
|149|--kubelet-client-certificate string|Path to a client cert file for TLS.|
|150|--kubelet-client-key string|Path to a client key file for TLS.|
|151|--kubelet-https     Default: true|Use https for kubelet connections.|
|152|--kubelet-preferred-address-types stringSlice     Default: [Hostname,InternalDNS,InternalIP,ExternalDNS,ExternalIP]|List of the preferred NodeAddressTypes to use for kubelet connections.|
|153|--kubelet-read-only-port uint     Default: 10255|DEPRECATED: kubelet port.|
|154|--kubelet-timeout duration     Default: 5s|Timeout for kubelet operations.|
|155|--kubernetes-service-node-port int|If non-zero, the Kubernetes master service (which apiserver creates/maintains) will be of type NodePort, using this as the value of the port. If zero, the Kubernetes master service will be of type ClusterIP.|
|156|--log-backtrace-at traceLocation     Default: :0|when logging hits line file:N, emit a stack trace|
|157|--log-dir string|If non-empty, write log files in this directory|
|158|--log-file string|If non-empty, use this log file|
|159|--log-flush-frequency duration     Default: 5s|Maximum number of seconds between log flushes|
|160|--logtostderr     Default: true|log to standard error instead of files|
|161|--master-service-namespace string     Default: "default"|DEPRECATED: the namespace from which the kubernetes master services should be injected into pods.|
|162|--max-connection-bytes-per-sec int|If non-zero, throttle each user connection to this number of bytes/sec. Currently only applies to long-running requests.|
|163|--max-mutating-requests-inflight int     Default: 200|The maximum number of mutating requests in flight at a given time. When the server exceeds this, it rejects requests. Zero for no limit.|
|164|--max-requests-inflight int     Default: 400|The maximum number of non-mutating requests in flight at a given time. When the server exceeds this, it rejects requests. Zero for no limit.|
|165|--min-request-timeout int     Default: 1800|An optional field indicating the minimum number of seconds a handler must keep a request open before timing it out. Currently only honored by the watch request handler, which picks a randomized value above this number as the connection timeout, to spread out load.|
|166|--oidc-ca-file string|If set, the OpenID server's certificate will be verified by one of the authorities in the oidc-ca-file, otherwise the host's root CA set will be used.|
|167|--oidc-client-id string|The client ID for the OpenID Connect client, must be set if oidc-issuer-url is set.|
|168|--oidc-groups-claim string|If provided, the name of a custom OpenID Connect claim for specifying user groups. The claim value is expected to be a string or array of strings. This flag is experimental, please see the authentication documentation for further details.|
|169|--oidc-groups-prefix string|If provided, all groups will be prefixed with this value to prevent conflicts with other authentication strategies.|
|170|--oidc-issuer-url string|The URL of the OpenID issuer, only HTTPS scheme will be accepted. If set, it will be used to verify the OIDC JSON Web Token (JWT).|
|171|--oidc-required-claim mapStringString|A key=value pair that describes a required claim in the ID Token. If set, the claim is verified to be present in the ID Token with a matching value. Repeat this flag to specify multiple claims.|
|172|--oidc-signing-algs stringSlice     Default: [RS256]|Comma-separated list of allowed JOSE asymmetric signing algorithms. JWTs with a 'alg' header value not in this list will be rejected. Values are defined by RFC 7518 https://tools.ietf.org/html/rfc7518#section-3.1.|
|173|--oidc-username-claim string     Default: "sub"|The OpenID claim to use as the user name. Note that claims other than the default ('sub') is not guaranteed to be unique and immutable. This flag is experimental, please see the authentication documentation for further details.|
|174|--oidc-username-prefix string|If provided, all usernames will be prefixed with this value. If not provided, username claims other than 'email' are prefixed by the issuer URL to avoid clashes. To skip any prefixing, provide the value '-'.|
|175|--profiling     Default: true|Enable profiling via web interface host:port/debug/pprof/|
|176|--proxy-client-cert-file string|Client certificate used to prove the identity of the aggregator or kube-apiserver when it must call out during a request. This includes proxying requests to a user api-server and calling out to webhook admission plugins. It is expected that this cert includes a signature from the CA in the --requestheader-client-ca-file flag. That CA is published in the 'extension-apiserver-authentication' configmap in the kube-system namespace. Components receiving calls from kube-aggregator should use that CA to perform their half of the mutual TLS verification.|
|177|--proxy-client-key-file string|Private key for the client certificate used to prove the identity of the aggregator or kube-apiserver when it must call out during a request. This includes proxying requests to a user api-server and calling out to webhook admission plugins.|
|178|--request-timeout duration     Default: 1m0s|An optional field indicating the duration a handler must keep a request open before timing it out. This is the default request timeout for requests but may be overridden by flags such as --min-request-timeout for specific types of requests.|
|179|--requestheader-allowed-names stringSlice|List of client certificate common names to allow to provide usernames in headers specified by --requestheader-username-headers. If empty, any client certificate validated by the authorities in --requestheader-client-ca-file is allowed.|
|180|--requestheader-client-ca-file string|Root certificate bundle to use to verify client certificates on incoming requests before trusting usernames in headers specified by --requestheader-username-headers. WARNING: generally do not depend on authorization being already done for incoming requests.|
|181|--requestheader-extra-headers-prefix stringSlice|List of request header prefixes to inspect. X-Remote-Extra- is suggested.|
|182|--requestheader-group-headers stringSlice|List of request headers to inspect for groups. X-Remote-Group is suggested.|
|183|--requestheader-username-headers stringSlice|List of request headers to inspect for usernames. X-Remote-User is common.|
|184|--runtime-config mapStringString|A set of key=value pairs that describe runtime configuration that may be passed to apiserver. <group>/<version> (or <version> for the core group) key can be used to turn on/off specific api versions. api/all is special key to control all api versions, be careful setting it false, unless you know what you do. api/legacy is deprecated, we will remove it in the future, so stop using it.|
|185|--secure-port int     Default: 6443|The port on which to serve HTTPS with authentication and authorization.It cannot be switched off with 0.|
|186|--service-account-issuer string|Identifier of the service account token issuer. The issuer will assert this identifier in "iss" claim of issued tokens. This value is a string or URI.|
|187|--service-account-key-file stringArray|File containing PEM-encoded x509 RSA or ECDSA private or public keys, used to verify ServiceAccount tokens. The specified file can contain multiple keys, and the flag can be specified multiple times with different files. If unspecified, --tls-private-key-file is used. Must be specified when --service-account-signing-key is provided|
|188|--service-account-lookup     Default: true|If true, validate ServiceAccount tokens exist in etcd as part of authentication.|
|189|--service-account-max-token-expiration duration|The maximum validity duration of a token created by the service account token issuer. If an otherwise valid TokenRequest with a validity duration larger than this value is requested, a token will be issued with a validity duration of this value.|
|190|--service-account-signing-key-file string|Path to the file that contains the current private key of the service account token issuer. The issuer will sign issued ID tokens with this private key. (Requires the 'TokenRequest' feature gate.)|
|191|--service-cluster-ip-range ipNet     Default: 10.0.0.0/24|A CIDR notation IP range from which to assign service cluster IPs. This must not overlap with any IP ranges assigned to nodes for pods.|
|192|--service-node-port-range portRange     Default: 30000-32767|A port range to reserve for services with NodePort visibility. Example: '30000-32767'. Inclusive at both ends of the range.|
|193|--skip-headers|If true, avoid header prefixes in the log messages|
|194|--stderrthreshold severity     Default: 2|logs at or above this threshold go to stderr|
|195|--storage-backend string|The storage backend for persistence. Options: 'etcd3' (default).|
|196|--storage-media-type string     Default: "application/vnd.kubernetes.protobuf"|The media type to use to store objects in storage. Some resources or storage backends may only support a specific media type and will ignore this setting.|
|197|--target-ram-mb int|Memory limit for apiserver in MB (used to configure sizes of caches, etc.)|
|198|--tls-cert-file string|File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated after server cert). If HTTPS serving is enabled, and --tls-cert-file and --tls-private-key-file are not provided, a self-signed certificate and key are generated for the public address and saved to the directory specified by --cert-dir.|
|199|--tls-cipher-suites stringSlice|Comma-separated list of cipher suites for the server. If omitted, the default Go cipher suites will be use. Possible values: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_RC4_128_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_RC4_128_SHA|
|200|--tls-min-version string|Minimum TLS version supported. Possible values: VersionTLS10, VersionTLS11, VersionTLS12|
|201|--tls-private-key-file string|File containing the default x509 private key matching --tls-cert-file.|
|202|--tls-sni-cert-key namedCertKey     Default: []|A pair of x509 certificate and private key file paths, optionally suffixed with a list of domain patterns which are fully qualified domain names, possibly with prefixed wildcard segments. If no domain patterns are provided, the names of the certificate are extracted. Non-wildcard matches trump over wildcard matches, explicit domain patterns trump over extracted names. For multiple key/certificate pairs, use the --tls-sni-cert-key multiple times. Examples: "example.crt,example.key" or "foo.crt,foo.key:*.foo.com,foo.com".|
|203|--token-auth-file string|If set, the file that will be used to secure the secure port of the API server via token authentication.|
|204|-v, --v Level|number for the log level verbosity|
|205|--version version[=true]|Print version information and quit|
|206|--vmodule moduleSpec|comma-separated list of pattern=N settings for file-filtered logging|
|207|--watch-cache     Default: true|Enable watch caching in the apiserver|
|208|--watch-cache-sizes stringSlice|Watch cache size settings for some resources (pods, nodes, etc.), comma separated. The individual setting format: resource[.group]#size, where resource is lowercase plural (no version), group is omitted for resources of apiVersion v1 (the legacy core API) and included for others, and size is a number. It takes effect when watch-cache is enabled. Some resources (replicationcontrollers, endpoints, nodes, pods, services, apiservices.apiregistration.k8s.io) have system defaults set by heuristics, others default to default-watch-cache-size|
