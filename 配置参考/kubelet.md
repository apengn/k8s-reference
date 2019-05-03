# kubelet
### 简介
The kubelet is the primary “node agent” that runs on each node. The kubelet works in terms of a PodSpec. A PodSpec is a YAML or JSON object that describes a pod. The kubelet takes a set of PodSpecs that are provided through various mechanisms (primarily through the apiserver) and ensures that the containers described in those PodSpecs are running and healthy. The kubelet doesn’t manage containers which were not created by Kubernetes.

Other than from a PodSpec from the apiserver, there are three ways that a container manifest can be provided to the Kubelet.

File: Path passed as a flag on the command line. Files under this path will be monitored periodically for updates. The monitoring period is 20s by default and is configurable via a flag.

HTTP endpoint: HTTP endpoint passed as a parameter on the command line. This endpoint is checked every 20 seconds (also configurable with a flag).

HTTP server: The kubelet can also listen for HTTP and respond to a simple API (underspec’d currently) to submit a new manifest.

#### Pod Lifecycle Event Generator (PLEG)
The Pod Lifecycle Event Generator is a function of the kubelet that creates a list of the states for all containers and pods then compares it to the previous states of the containers and pods in a process called Relisting. This allows the PLEG to know which pods and containers need to be synced. In versions prior to 1.2, this was accomplished by polling and was CPU intensive. By changing to this method, this significantly reduced resource utilization allowing for better container density.

`kubelet [flags]`
### 选项
| ID | 参数 |说明 |
| :-: | :---------- | :---------- |
|1|--address 0.0.0.0|kubelet服务监听的IP地址（设置为 0.0.0.0 监听所有IPv4地址，“::”监听所有IPv6地址）（默认 0.0.0.0）|
|2|--allow-privileged|如果为true ，将允许容器请求特权模式|
|3|--alsologtostderr|同时输出日志到标准错误控制台和文件|
|4|--anonymous-auth|允许匿名请求到kubelet服务。未被其他身份验证方法拒绝的请求将被视为匿名请求。 匿名请求包含用户名system:anonymous，以及组名system:unauthenticated（默认 true）|
|5|--application-metrics-count-limit int|应用metric保留的最大数量（每个容器）（默认 100）|
|6|--authentication-token-webhook|使用TokenReview API鉴定令牌的身份验证|
|7|--authentication-token-webhook-cache-ttl duration|webhook令牌身份验证器缓存响应时间。（默认 2m0s）|
|8|--authorization-mode string|kubelet 服务的授权模式。有效的选项是AlwaysAllow或Webhook。Webhook模式使用 SubjectAccessReview API来确定授权（默认“AlwaysAllow”）|
|9|--authorization-webhook-cache-authorized-ttl duration|webhook的已认证响应缓存时间（默认 5m0s）|
|10|--authorization-webhook-cache-unauthorized-ttl duration|The duration to cache 'unauthorized' responses from the webhook authorizer. (default 30s)|
|11|--azure-container-registry-config string|Path to the file container Azure container registry configuration information.|
|12|--boot-id-file string|Comma-separated list of files to check for boot-id. Use the first one that exists. (default "/proc/sys/kernel/random/boot_id")|
|13|--bootstrap-checkpoint-path string|Path to the directory where the checkpoints are stored|
|14|--bootstrap-kubeconfig string|Path to a kubeconfig file that will be used to get client certificate for kubelet. If the file specified by --kubeconfig does not exist, the bootstrap kubeconfig is used to request a client certificate from the API server. On success, a kubeconfig file referencing the generated client certificate and key is written to the path specified by --kubeconfig. The client certificate and key file will be stored in the directory pointed by --cert-dir.|
|15|--cert-dir string|The directory where the TLS certs are located. If --tls-cert-file and --tls-private-key-file are provided, this flag will be ignored. (default "/var/lib/kubelet/pki")|
|16|--cgroup-driver string|Driver that the kubelet uses to manipulate cgroups on the host.|
|17|--cgroup-root string|Optional root cgroup to use for pods. This is handled by the container runtime on a best effort basis. Default: '', which means use the container runtime default.|
|18|--cgroups-per-qos|Enable creation of QoS cgroup hierarchy, if true top level QoS and pod cgroups are created. (default true)|
|19|--chaos-chance float|If > 0.0, introduce random client errors and latency. Intended for testing.|
|20|--client-ca-file string|If set, any request presenting a client certificate signed by one of the authorities in the client-ca-file is authenticated with an identity corresponding to the CommonName of the client certificate.|
|21|--cloud-config string|The path to the cloud provider configuration file.|
|22|--cloud-provider string|The provider for cloud services. Specify empty string for running with no cloud provider.|
|23|--cloud-provider-gce-lb-src-cidrs cidrs|CIDRs opened in GCE firewall for LB traffic proxy & health checks (default 130.211.0.0/22,35.191.0.0/16,209.85.152.0/22,209.85.204.0/22)|
|24|--cluster-dns stringSlice|Comma-separated list of DNS server IP address.|
|25|--cluster-domain string|Domain for this cluster.|
|26|--cni-bin-dir string|The full path of the directory in which to search for CNI plugin binaries. Default: /opt/cni/bin|
|27|--cni-conf-dir string|The full path of the directory in which to search for CNI config files. Default: /etc/cni/net.d|
|28|--container-hints string|location of the container hints file (default "/etc/cadvisor/container_hints.json")|
|29|--container-runtime string|The container runtime to use. Possible values: 'docker', 'remote', 'rkt(deprecated)'. (default "docker")|
|30|--container-runtime-endpoint string|[Experimental] The endpoint of remote runtime service. Currently unix socket is supported on Linux, and tcp is supported on windows.|
|31|--containerd string|containerd endpoint (default "unix:///var/run/containerd.sock")|
|32|--containerized|Experimental support for running kubelet in a container.|
|33|--contention-profiling|Enable lock contention profiling, if profiling is enabled|
|34|--cpu-cfs-quota|Enable CPU CFS quota enforcement for containers that specify CPU limits (default true)|
|35|--cpu-manager-policy string|CPU Manager policy to use. Possible values: 'none', 'static'. (default "none")|
|36|--cpu-manager-reconcile-period NodeStatusUpdateFrequency|CPU Manager reconciliation period. Examples: '10s', or '1m'. If not supplied, defaults to NodeStatusUpdateFrequency (default 10s)|
|37|--docker string|docker endpoint (default "unix:///var/run/docker.sock")|
|38|--docker-disable-shared-pid|The Container Runtime Interface (CRI) defaults to using a shared PID namespace for containers in a pod when running with Docker 1.13.1 or higher. Setting this flag reverts to the previous behavior of isolated PID namespaces. This ability will be removed in a future Kubernetes release. (default true)|
|39|--docker-endpoint string|Use this for the docker endpoint to communicate with (default "unix:///var/run/docker.sock")|
|40|--docker-env-metadata-whitelist string|a comma-separated list of environment variable keys that needs to be collected for docker containers|
|41|--docker-only|Only report docker containers in addition to root stats|
|42|--docker-root string|DEPRECATED: docker root is read from docker info (this is a fallback, default: /var/lib/docker) (default "/var/lib/docker")|
|43|--docker-tls|use TLS to connect to docker|
|44|--docker-tls-ca string|path to trusted CA (default "ca.pem")|
|45|--docker-tls-cert string|path to client certificate (default "cert.pem")|
|46|--docker-tls-key string|path to private key (default "key.pem")|
|47|--dynamic-config-dir string|The Kubelet will use this directory for checkpointing downloaded configurations and tracking configuration health. The Kubelet will create this directory if it does not already exist. The path may be absolute or relative; relative paths start at the Kubelet's current working directory. Providing this flag enables dynamic Kubelet configuration. Presently, you must also enable the DynamicKubeletConfig feature gate to pass this flag.|
|48|--enable-controller-attach-detach|Enables the Attach/Detach controller to manage attachment/detachment of volumes scheduled to this node, and disables kubelet from executing any attach/detach operations (default true)|
|49|--enable-debugging-handlers|Enables server endpoints for log collection and local running of containers and commands (default true)|
|50|--enable-load-reader|Whether to enable cpu load reader|
|51|--enable-server|Enable the Kubelet's server (default true)|
|52|--enforce-node-allocatable stringSlice|A comma separated list of levels of node allocatable enforcement to be enforced by kubelet. Acceptable options are 'pods', 'system-reserved' & 'kube-reserved'. If the latter two options are specified, '--system-reserved-cgroup' & '--kube-reserved-cgroup' must also be set respectively. See /docs/tasks/administer-cluster/reserve-compute-resources/ for more details. (default [pods])|
|53|--event-burst int32|Maximum size of a bursty event records, temporarily allows event records to burst to this number, while still not exceeding event-qps. Only used if --event-qps > 0 (default 10)|
|54|--event-qps int32|If > 0, limit event creations per second to this value. If 0, unlimited. (default 5)|
|55|--event-storage-age-limit string|Max length of time for which to store events (per type). Value is a comma separated list of key values, where the keys are event types (e.g.: creation, oom) or "default" and the value is a duration. Default is applied to all non-specified event types (default "default=0")|
|56|--event-storage-event-limit string|Max number of events to store (per type). Value is a comma separated list of key values, where the keys are event types (e.g.: creation, oom) or "default" and the value is an integer. Default is applied to all non-specified event types (default "default=0")|
|57|--eviction-hard mapStringString|A set of eviction thresholds (e.g. memory.available<1Gi) that if met would trigger a pod eviction. (default imagefs.available<15%,memory.available<100Mi,nodefs.available<10%,nodefs.inodesFree<5%)|
|58|--eviction-max-pod-grace-period int32|Maximum allowed grace period (in seconds) to use when terminating pods in response to a soft eviction threshold being met.|
|59|--eviction-minimum-reclaim mapStringString|A set of minimum reclaims (e.g. imagefs.available=2Gi) that describes the minimum amount of resource the kubelet will reclaim when performing a pod eviction if that resource is under pressure.|
|60|--eviction-pressure-transition-period duration|Duration for which the kubelet has to wait before transitioning out of an eviction pressure condition. (default 5m0s)|
|61|--eviction-soft mapStringString|A set of eviction thresholds (e.g. memory.available<1.5Gi) that if met over a corresponding grace period would trigger a pod eviction.|
|62|--eviction-soft-grace-period mapStringString|A set of eviction grace periods (e.g. memory.available=1m30s) that correspond to how long a soft eviction threshold must hold before triggering a pod eviction.|
|63|--exit-on-lock-contention|Whether kubelet should exit upon lock-file contention.|
|64|--experimental-allocatable-ignore-eviction|When set to 'true', Hard Eviction Thresholds will be ignored while calculating Node Allocatable. See /docs/tasks/administer-cluster/reserve-compute-resources/ for more details. [default=false]|
|65|--experimental-allowed-unsafe-sysctls stringSlice|Comma-separated whitelist of unsafe sysctls or unsafe sysctl patterns (ending in *). Use these at your own risk.|
|66|--experimental-bootstrap-kubeconfig string|deprecated: use --bootstrap-kubeconfig|
|67|--experimental-check-node-capabilities-before-mount|[Experimental] if set true, the kubelet will check the underlying node for required components (binaries, etc.) before performing the mount|
|68|--experimental-kernel-memcg-notification|If enabled, the kubelet will integrate with the kernel memcg notification to determine if memory eviction thresholds are crossed rather than polling.|
|69|--experimental-mounter-path string|[Experimental] Path of mounter binary. Leave empty to use the default mount.|
|70|--experimental-qos-reserved mapStringString|A set of ResourceName=Percentage (e.g. memory=50%) pairs that describe how pod resource requests are reserved at the QoS level. Currently only memory is supported. [default=none]|
|71|--fail-swap-on|Makes the Kubelet fail to start if swap is enabled on the node.|
|72|--feature-gates mapStringBool|A set of key=value pairs that describe feature gates for alpha/experimental features. Options are:|
|73||APIListChunking=true|false (BETA - default=true)|
|74||APIResponseCompression=true|false (ALPHA - default=false)|
|75||Accelerators=true|false|
|76||AdvancedAuditing=true|false (BETA - default=true)|
|77||AllAlpha=true|false (ALPHA - default=false)|
|78||AllowExtTrafficLocalEndpoints=true|false|
|79||AppArmor=true|false (BETA - default=true)|
|80||BlockVolume=true|false (ALPHA - default=false)|
|81||CPUManager=true|false (BETA - default=true)|
|82||CSIPersistentVolume=true|false (ALPHA - default=false)|
|83||CustomPodDNS=true|false (ALPHA - default=false)|
|84||CustomResourceValidation=true|false (BETA - default=true)|
|85||DebugContainers=true|false|
|86||DevicePlugins=true|false (ALPHA - default=false)|
|87||DynamicKubeletConfig=true|false (ALPHA - default=false)|
|88||EnableEquivalenceClassCache=true|false (ALPHA - default=false)|
|89||ExpandPersistentVolumes=true|false (ALPHA - default=false)|
|90||ExperimentalCriticalPodAnnotation=true|false (ALPHA - default=false)|
|91||ExperimentalHostUserNamespaceDefaulting=true|false (BETA - default=false)|
|92||HugePages=true|false (ALPHA - default=false)|
|93||Initializers=true|false (ALPHA - default=false)|
|94||KubeletConfigFile=true|false (ALPHA - default=false)|
|95||LocalStorageCapacityIsolation=true|false (ALPHA - default=false)|
|96||MountContainers=true|false (ALPHA - default=false)|
|97||MountPropagation=true|false (ALPHA - default=false)|
|98||PVCProtection=true|false (ALPHA - default=false)|
|99||PersistentLocalVolumes=true|false (ALPHA - default=false)|
|100||PodPriority=true|false (ALPHA - default=false)|
|101||ReadOnlyAPIDataVolumes=true|false|
|102||ResourceLimitsPriorityFunction=true|false (ALPHA - default=false)|
|103||RotateKubeletClientCertificate=true|false (BETA - default=true)|
|104||RotateKubeletServerCertificate=true|false (ALPHA - default=false)|
|105||ServiceNodeExclusion=true|false (ALPHA - default=false)|
|106||ServiceProxyAllowExternalIPs=true|false|
|107||StreamingProxyRedirects=true|false (BETA - default=true)|
|108||SupportIPVSProxyMode=true|false (ALPHA - default=false)|
|109||TaintBasedEvictions=true|false (BETA - default=true)|
|110||TaintNodesByCondition=true|false (BETA - default=true)|
|111||VolumeScheduling=true|false (ALPHA - default=false)|
|112||VolumeSubpath=true|false|
|113|--file-check-frequency duration|Duration between checking config files for new data (default 20s)|
|114|--global-housekeeping-interval duration|Interval between global housekeepings (default 1m0s)|
|115|--google-json-key string|The Google Cloud Platform Service Account JSON Key to use for authentication.|
|116|--hairpin-mode string|How should the kubelet setup hairpin NAT. This allows endpoints of a Service to loadbalance back to themselves if they should try to access their own Service. Valid values are "promiscuous-bridge", "hairpin-veth" and "none". (default "promiscuous-bridge")|
|117|--healthz-bind-address 0.0.0.0|The IP address for the healthz server to serve on (set to 0.0.0.0 for all IPv4 interfaces and `::` for all IPv6 interfaces) (default 127.0.0.1)|
|118|--healthz-port int32|The port of the localhost healthz endpoint (set to 0 to disable) (default 10248)|
|119|--host-ipc-sources stringSlice|Comma-separated list of sources from which the Kubelet allows pods to use the host ipc namespace. (default [*])|
|120|--host-network-sources stringSlice|Comma-separated list of sources from which the Kubelet allows pods to use of host network. (default [*])|
|121|--host-pid-sources stringSlice|Comma-separated list of sources from which the Kubelet allows pods to use the host pid namespace. (default [*])|
|122|--hostname-override string|If non-empty, will use this string as identification instead of the actual hostname.|
|123|--housekeeping-interval duration|Interval between container housekeepings (default 10s)|
|124|--http-check-frequency duration|Duration between checking http for new data (default 20s)|
|125|--image-gc-high-threshold int32|The percent of disk usage after which image garbage collection is always run. (default 85)|
|126|--image-gc-low-threshold int32|The percent of disk usage before which image garbage collection is never run. Lowest disk usage to garbage collect to. (default 80)|
|127|--image-pull-progress-deadline duration|If no pulling progress is made before this deadline, the image pulling will be cancelled. (default 1m0s)|
|128|--image-service-endpoint string|[Experimental] The endpoint of remote image service. If not specified, it will be the same with container-runtime-endpoint by default. Currently unix socket is supported on Linux, and tcp is supported on windows.|
|129|--init-config-dir string|The Kubelet will look in this directory for the init configuration. The path may be absolute or relative; relative paths start at the Kubelet's current working directory. Omit this argument to use the built-in default configuration values. Presently, you must also enable the KubeletConfigFile feature gate to pass this flag.|
|130|--iptables-drop-bit int32|The bit of the fwmark space to mark packets for dropping. Must be within the range [0, 31]. (default 15)|
|131|--iptables-masquerade-bit int32|The bit of the fwmark space to mark packets for SNAT. Must be within the range [0, 31]. Please match this parameter with corresponding parameter in kube-proxy. (default 14)|
|132|--kube-api-burst int32|Burst to use while talking with kubernetes apiserver (default 10)|
|133|--kube-api-content-type string|Content type of requests sent to apiserver. (default "application/vnd.kubernetes.protobuf")|
|134|--kube-api-qps int32|QPS to use while talking with kubernetes apiserver (default 5)|
|135|--kube-reserved mapStringString|A set of ResourceName=ResourceQuantity (e.g. cpu=200m,memory=500Mi,ephemeral-storage=1Gi,pid=1000) pairs that describe resources reserved for kubernetes system components. Currently cpu, memory, pid, and local ephemeral storage for root file system are supported. See http://kubernetes.io/docs/user-guide/compute-resources for more detail. [default=none]|
|136|--kube-reserved-cgroup string|Absolute name of the top level cgroup that is used to manage kubernetes components for which compute resources were reserved via '--kube-reserved' flag. Ex. '/kube-reserved'. [default='']|
|137|--kubeconfig string|Path to a kubeconfig file, specifying how to connect to the API server. Providing --kubeconfig enables API server mode, omitting --kubeconfig enables standalone mode.|
|138|--kubelet-cgroups string|Optional absolute name of cgroups to create and run the Kubelet in.|
|139|--lock-file string|The path to file for kubelet to use as a lock file.|
|140|--log-backtrace-at traceLocation|when logging hits line file:N, emit a stack trace (default :0)|
|141|--log-cadvisor-usage|Whether to log the usage of the cAdvisor container|
|142|--log-dir string|If non-empty, write log files in this directory|
|143|--log-flush-frequency duration|Maximum number of seconds between log flushes (default 5s)|
|144|--logtostderr|log to standard error instead of files (default true)|
|145|--machine-id-file string|Comma-separated list of files to check for machine-id. Use the first one that exists. (default "/etc/machine-id,/var/lib/dbus/machine-id")|
|146|--make-iptables-util-chains|If true, kubelet will ensure iptables utility rules are present on host. (default true)|
|147|--manifest-url string|URL for accessing the container manifest|
|148|--manifest-url-header --manifest-url-header 'a:hello,b:again,c:world' --manifest-url-header 'b:beautiful'|Comma-separated list of HTTP headers to use when accessing the manifest URL. Multiple headers with the same name will be added in the same order provided. This flag can be repeatedly invoked. For example: --manifest-url-header 'a:hello,b:again,c:world' --manifest-url-header 'b:beautiful'|
|149|--max-open-files int|Number of files that can be opened by Kubelet process. (default 1000000)|
|150|--max-pods int32|Number of Pods that can run on this Kubelet. (default 110)|
|151|--minimum-image-ttl-duration duration|Minimum age for an unused image before it is garbage collected.|
|152|--network-plugin string|The name of the network plugin to be invoked for various events in kubelet/pod lifecycle|
|153|--network-plugin-mtu int32|The MTU to be passed to the network plugin, to override the default. Set to 0 to use the default 1460 MTU.|
|154|--node-ip string|IP address of the node. If set, kubelet will use this IP address for the node|
|155|--node-labels mapStringString|Labels to add when registering the node in the cluster.|
|156|--node-status-update-frequency duration|Specifies how often kubelet posts node status to master. Note: be cautious when changing the constant, it must work with nodeMonitorGracePeriod in nodecontroller. (default 10s)|
|157|--oom-score-adj int32|The oom-score-adj value for kubelet process. Values must be within the range [-1000, 1000] (default -999)|
|158|--pod-cidr string|The CIDR to use for pod IP addresses, only used in standalone mode.|
|159|--pod-infra-container-image string|The image whose network/ipc namespaces containers in each pod will use. (default "k8s.gcr.io/pause:3.1")|
|160|--pod-manifest-path string|Path to the directory containing pod manifest files to run, or the path to a single pod manifest file. Files starting with dots will be ignored.|
|161|--pods-per-core int32|Number of Pods per core that can run on this Kubelet. The total number of Pods on this Kubelet cannot exceed max-pods, so max-pods will be used if this calculation results in a larger number of Pods allowed on the Kubelet. A value of 0 disables this limit.|
|162|--port int32|The port for the Kubelet to serve on. (default 10250)|
|163|--protect-kernel-defaults|Default kubelet behaviour for kernel tuning. If set, kubelet errors if any of kernel tunables is different than kubelet defaults.|
|164|--provider-id string|Unique identifier for identifying the node in a machine database, i.e cloudprovider|
|165|--read-only-port int32|The read-only port for the Kubelet to serve on with no authentication/authorization (set to 0 to disable) (default 10255)|
|166|--really-crash-for-testing|If true, when panics occur crash. Intended for testing.|
|167|--register-node|Register the node with the apiserver. If --kubeconfig is not provided, this flag is irrelevant, as the Kubelet won't have an apiserver to register with. Default=true. (default true)|
|168|--register-with-taints []api.Taint|Register the node with the given list of taints (comma separated "=:"). No-op if register-node is false.|
|169|--registry-burst int32|Maximum size of bursty pulls, temporarily allows pulls to burst to this number, while still not exceeding registry-qps. Only used if --registry-qps > 0 (default 10)|
|170|--registry-qps int32|If > 0, limit registry pull QPS to this value.|
|171|--resolv-conf string|Resolver configuration file used as the basis for the container DNS resolution configuration. (default "/etc/resolv.conf")|
|172|--root-dir string|Directory path for managing kubelet files (volume mounts,etc). (default "/var/lib/kubelet")|
|173|--rotate-certificates|Auto rotate the kubelet client certificates by requesting new certificates from the kube-apiserver when the certificate expiration approaches.|
|174|--rotate-server-certificates|Auto-request and rotate the kubelet serving certificates by requesting new certificates from the kube-apiserver when the certificate expiration approaches. Requires the RotateKubeletServerCertificate feature gate to be enabled, and approval of the submitted CertificateSigningRequest objects.|
|175|--runonce|If true, exit after spawning pods from local manifests or remote urls. Exclusive with --enable-server|
|176|--runtime-cgroups string|Optional absolute name of cgroups to create and run the runtime in.|
|177|--runtime-request-timeout duration|Timeout of all runtime requests except long running request - pull, logs, exec and attach. When timeout exceeded, kubelet will cancel the request, throw out an error and retry later. (default 2m0s)|
|178|--seccomp-profile-root string|Directory path for seccomp profiles. (default "/var/lib/kubelet/seccomp")|
|179|--serialize-image-pulls|Pull images one at a time. We recommend *not* changing the default value on nodes that run docker daemon with version < 1.9 or an Aufs storage backend. Issue #10959 has more details. (default true)|
|180|--stderrthreshold severity|logs at or above this threshold go to stderr (default 2)|
|181|--storage-driver-buffer-duration duration|Writes in the storage driver will be buffered for this duration, and committed to the non memory backends as a single transaction (default 1m0s)|
|182|--storage-driver-db string|database name (default "cadvisor")|
|183|--storage-driver-host string|database host:port (default "localhost:8086")|
|184|--storage-driver-password string|database password (default "root")|
|185|--storage-driver-secure|use secure connection with database|
|186|--storage-driver-table string|table name (default "stats")|
|187|--storage-driver-user string|database username (default "root")|
|188|--streaming-connection-idle-timeout duration|Maximum time a streaming connection can be idle before the connection is automatically closed. 0 indicates no timeout. Example: '5m' (default 4h0m0s)|
|189|--sync-frequency duration|Max period between synchronizing running containers and config (default 1m0s)|
|190|--system-cgroups /|Optional absolute name of cgroups in which to place all non-kernel processes that are not already inside a cgroup under /. Empty for no container. Rolling back the flag requires a reboot.|
|191|--system-reserved mapStringString|A set of ResourceName=ResourceQuantity (e.g. cpu=200m,memory=500Mi,ephemeral-storage=1Gi,pid=1000) pairs that describe resources reserved for non-kubernetes components. Currently only cpu, memory, and pid are supported. See http://kubernetes.io/docs/user-guide/compute-resources for more detail. [default=none]|
|192|--system-reserved-cgroup string|Absolute name of the top level cgroup that is used to manage non-kubernetes components for which compute resources were reserved via '--system-reserved' flag. Ex. '/system-reserved'. [default='']|
|193|--tls-cert-file string|File containing x509 Certificate used for serving HTTPS (with intermediate certs, if any, concatenated after server cert). If --tls-cert-file and --tls-private-key-file are not provided, a self-signed certificate and key are generated for the public address and saved to the directory passed to --cert-dir.|
|194|--tls-cipher-suites stringSlice|Comma-separated list of cipher suites for the server. If omitted, the default Go cipher suites will be used. Possible values: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_RC4_128_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_RC4_128_SHA|
|195|--tls-private-key-file string|File containing x509 private key matching --tls-cert-file.|
|196|-v, --v Level|log level for V logs|
|197|--version version[=true]|Print version information and quit|
|198|--vmodule moduleSpec|comma-separated list of pattern=N settings for file-filtered logging|
|199|--volume-plugin-dir string|The full path of the directory in which to search for additional third party volume plugins (default "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/")|
|200|--volume-stats-agg-period duration|Specifies interval for kubelet to calculate and cache the volume disk usage for all pods and volumes.|
|201|-h, --help|help for kubelet|
