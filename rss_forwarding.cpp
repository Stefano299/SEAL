/// This example has been developed by using
/// the DOCA 2.9.2 LST version, whose documentation
/// can be found at this link:
/// https://docs.nvidia.com/doca/archive/2-9-2/index.html

// Ideas to better undestand DOCA:
//  - run this application using a different number of CPU cores
//      try with -c/-l DPDK options
//  - change burst size to make sw able to send and a receive
//      a greater number of packets at the same time
//  - do experiments with the rte_mempool: try to configure
//      a per thread cache, change its size, and so on
//  - try to measure application performances by using perf
//      and other performance analysis tools

// C/C++ headers
#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <numeric>
#include <pthread.h>
#include <signal.h>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

// DPDK headers
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_flow.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_net.h>


// DOCA specific headers
#include <doca_argp.h>
#include <doca_flow.h>
#include <doca_log.h>

#include <seal/seal.h>
#include "packet_assembler.h"
#include "message.h"
// error check macros:
#define CHECK_NNEG(res) if ((res) < 0) { std::cerr << "result = " << (res) << std::endl; abort(); }
#define CHECK_DERR(derr) if ((derr) != DOCA_SUCCESS) \
    { \
        std::cerr << "doca_error_t = " << (int)(derr) << ' ' << doca_error_get_descr(derr) << std::endl; \
        std::cerr << "Error location = " << __FILE__ << ':' << __LINE__ << std::endl; \
        abort(); \
    }


// Used to manage IPv4 addresses
#define BE_IPV4_ADDR(a, b, c, d) (RTE_BE32(((uint32_t)a << 24) + (b << 16) + (c << 8) + d)) /* create IPV4 address */
struct ip_addr {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
};

using namespace seal;

// Classe per gestire operazioni omomorifiche
class HEContext {
public:
    //Uso puntatori per facilitare l'inizializzazione nel costruttore
    seal::SEALContext* context;
    Evaluator* evaluator;
    BatchEncoder* encoder;
    
    HEContext() {
        // Inizializzazione di SEAL
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(2048);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(2048));
        parms.set_plain_modulus(65537);
        
        context = new seal::SEALContext(parms);
        evaluator = new Evaluator(*context);
        encoder = new BatchEncoder(*context);
    }
    
    ~HEContext() {
        delete encoder;
        delete evaluator;
        delete context;
    }
    
    // Somma un numero in chiaro al ciphertext
    void add_plain_number(Ciphertext& ct, uint64_t number) {
        std::vector<uint64_t> values(encoder->slot_count(), number);
        Plaintext ptx;
        encoder->encode(values, ptx);
        evaluator->add_plain_inplace(ct, ptx);
    }
};

/// Structure containing the full configuration
/// of this application
struct app_005_cfg
{
    // DPDK configuration
    struct dpdk
    {
        // this application requires exactly 2 ports
        static constexpr int nb_required_eth_devices = 2;
        // DPDK, in order to handle packets in software, requires
        // mbuf allocation
        //  https://doc.dpdk.org/api/rte__mbuf_8h.html
        static constexpr char mbuf_pool_name[] = "MBUF_POOL";
        // number of element in the mbuf pool
        static constexpr int mbuf_pool_size = (1 << 14) - 1;
        // size reserver for each packet, I do not expect
        // packets to be bigger than that (no jumboframes)
        static constexpr int mbuf_pool_pkt_buf_size = (1 << 11);

        struct {
            uint16_t port_id = 0;
        } ingress;

        struct {
            uint16_t port_id = 0;
        } egress;

        // total number of active threads managed by
        // DPDK:
        int nb_dpdk_threads = 0;

        // number RX and TX queues for NIC-SW interaction
        // the actual number of queues is twice this
        // number per interface
        int nb_rxtx_queues = 0;
        std::vector<uint16_t> rxtx_queues;

        static constexpr uint16_t nb_ring_rx_size = 128;
        static constexpr uint16_t nb_ring_tx_size = 128;

        // pointer to buffer pool : must be deallocated
        // on application termination
        struct rte_mempool *mbuf_pool = nullptr;
    } dpdk;

    // DOCA configuration
    struct doca
    {
        struct doca_log_backend *sdk_log = nullptr;

        struct {
            struct doca_flow_port *port = nullptr;
            struct doca_flow_pipe *root_pipe = nullptr;
        } ingress;

        struct {
            struct doca_flow_port *port = nullptr;
            struct doca_flow_pipe *root_pipe = nullptr;
        } egress;
    } doca;
};


/// @brief Get configuration for this app to run
static struct app_005_cfg get_app_config()
{
    struct app_005_cfg cfg;

    // by default try to use all the cores/hardware queues
    cfg.dpdk.nb_rxtx_queues = 8;

    return cfg;
}


static doca_error_t configure_logger(struct app_005_cfg &cfg)
{
    doca_error_t result;

    std::cout << "Configuring DOCA logging...\n";
    result = doca_log_backend_create_standard();
    CHECK_DERR(result);
    result = doca_log_backend_create_with_file_sdk(stderr, &cfg.doca.sdk_log);
    CHECK_DERR(result);
    result = doca_log_backend_set_sdk_level(cfg.doca.sdk_log, DOCA_LOG_LEVEL_INFO);
    CHECK_DERR(result);
    std::cout << "DOCA logging configured\n";

    return DOCA_SUCCESS;
}

// This function should be passed to the DOCA
// 'doca_argp_set_dpdk_program' function to parse
// the DPDK specific arguments
static doca_error_t init_dpdk(int argc, char *argv[])
{
    int result;

    std::cout << "Starting DPDK RTE EAL..." << std::endl;
    // parse DPDK arguments, that are all the
    // arguments supplied to the application from
    // command line (main function) up to the '--'
    result = rte_eal_init(argc, argv);
    CHECK_NNEG(result);
    std::cout << "DPDK RTE EAL started" << std::endl;

    return DOCA_SUCCESS;
}


// controls what to do when application is invoked
// with "-- --version"
[[noreturn]] static doca_error_t my_doca_version_callback(void *param, void *doca_config)
{
    (void)param;
    (void)doca_config;

    const auto version = doca_version();
    const auto runtime_version = doca_version_runtime();

    std::cout << "DOCA SDK     Version (Compilation): " << version << std::endl;
    std::cout << "DOCA Runtime Version (Runtime):     " << runtime_version << std::endl;

    // sample application invoked this function
    // from --version callback
    doca_argp_destroy();

    exit(EXIT_SUCCESS);
}


static doca_error_t configure_doca_parser(struct app_005_cfg &cfg)
{
    doca_error_t result;

    std::cout << "Configuring DOCA parser..." << std::endl;

    // initialize DOCA parser - global object
    result = doca_argp_init("app_005_simple_l2_fwd_polling_only", &cfg);
    CHECK_DERR(result);

    doca_argp_set_dpdk_program(init_dpdk);

    // "--version" DOCA paramenter (must be preceded by '--')
    // is handled by the following function
    // Given function must not return!
    result = doca_argp_register_version_callback(my_doca_version_callback);
    CHECK_DERR(result);

    std::cout << "DOCA parser configured" << std::endl;

    return DOCA_SUCCESS;
}


static doca_error_t configure_dpdk_mbuf_pool(struct app_005_cfg::dpdk &dpdk)
{
    struct rte_mempool *mbuf_pool = nullptr;

    mbuf_pool = rte_pktmbuf_pool_create(
        app_005_cfg::dpdk::mbuf_pool_name,
        app_005_cfg::dpdk::mbuf_pool_size,
        /* per thread cache size */ 0,
        /* private (application) data size */ 0,
        app_005_cfg::dpdk::mbuf_pool_pkt_buf_size,
        rte_socket_id()
    );
    if (!mbuf_pool)
    {
        std::cerr << "rte_pktmbuf_pool_create failed" << std::endl;
        abort();
    }

    // set mbuf pool
    dpdk.mbuf_pool = mbuf_pool;

    return DOCA_SUCCESS;
}


// configure DPDK ports and queues
// initialize ingress and egress port queues
static doca_error_t configure_dpdk_ports_and_queues(struct app_005_cfg::dpdk &dpdk)
{
    doca_error_t result;
    int ret;

    // check and count available ethernet devices
    // Ethernet devices can be listed as DPDK arguments
    // with the use of the "-a" option
    // The syntax to be used with the -a option can be
    // seen by invoking the application passing --help to
    // the DPDK parse, but, shortly, it is:
    //  -a <[domain:]bus:devid.func>
    //
    // -a can be used for interfaces placed on the PCI
    // or the auxiliary bus, in such case the argument
    // can be built by combining the fields seen with
    // "ip -d link show" or 'parentbus' 'parentdev'.
    // Example:
    // 1. ip link output contains
    //      "parentbus auxiliary parentdev mlx5_core.sf.2"
    //  then DPDK argument is "-a auxiliary:mlx5_core.sf.2"
    // 2. ip link output contains
    //      "parentbus pci parentdev 0000:03:00.0"
    //  then DPDK argument is "-a pci:0000:03:00.0"
    ret = rte_eth_dev_count_avail();
    CHECK_NNEG(ret);
    if (ret != app_005_cfg::dpdk::nb_required_eth_devices)
    {
        std::cerr << "ERROR: " << ret << " but " << app_005_cfg::dpdk::nb_required_eth_devices << " required!" << std::endl;
        abort();
    }

    // check the number of available threads:
    ret = rte_lcore_count();  // Dipende dall'opzione di lancio
    CHECK_NNEG(ret);
    // number of threads activated by DPDK: it is
    // important because
    dpdk.nb_dpdk_threads = ret;
    // the number of useful threads is the minimum between
    // the number of expected queues and the CPU count
    // Non ha senso avere più code che thread
    dpdk.nb_rxtx_queues = std::min(dpdk.nb_rxtx_queues, ret);

    // handling packets in software requires packet buffers
    // to store packets
    result = configure_dpdk_mbuf_pool(dpdk);
    CHECK_DERR(result);

    // DPDK ports are associated with IDs:
    //  port 0 is the first port specified with "-a"
    //  port 1 is the second port specified with "-a"
    dpdk.ingress.port_id = 0;
    dpdk.egress.port_id = 1;

    // ensure port IDs are valid
    if (!rte_eth_dev_is_valid_port(dpdk.ingress.port_id))
    {
        std::cerr << "!rte_eth_dev_is_valid_port(" << dpdk.ingress.port_id << ")" << std::endl;
        abort();
    }
    if (!rte_eth_dev_is_valid_port(dpdk.egress.port_id))
    {
        std::cerr << "!rte_eth_dev_is_valid_port(" << dpdk.ingress.port_id << ")" << std::endl;
        abort();
    }

    {   // configure the ingress port
        struct rte_flow_error error;
        struct rte_eth_conf port_conf;

        memset(&error, 0, sizeof(error));
        memset(&port_conf, 0, sizeof(port_conf));

        // set isolated mode to default (so this call
        // is here simply as example, does nothing)
        //
        // Frome the doc:
        //  Calling this function as soon as possible
        //  after device initialization, ideally
        //  before the first call to rte_eth_dev_configure(),
        //  is recommended to avoid possible failures due
        //   to conflicting settings.
        ret = rte_flow_isolate(dpdk.ingress.port_id, 0, &error);
        CHECK_NNEG(ret);

        // set default conf
        ret = rte_eth_dev_configure(
            dpdk.ingress.port_id,
            // RX queues are all regular queues for software
            dpdk.nb_rxtx_queues,
            // TX queues are all regular queues for software
            dpdk.nb_rxtx_queues,
            &port_conf
        );
        CHECK_NNEG(ret);

        // allocate TX and RX queues
        for (int q = 0; q < dpdk.nb_rxtx_queues; ++q)
        {
            ret = rte_eth_rx_queue_setup(
                dpdk.ingress.port_id,
                q,
                app_005_cfg::dpdk::nb_ring_rx_size,
                rte_socket_id(),
                /* default conf */ nullptr,
                dpdk.mbuf_pool
            );
            CHECK_NNEG(ret);
            ret = rte_eth_tx_queue_setup(
                dpdk.ingress.port_id,
                q,
                app_005_cfg::dpdk::nb_ring_tx_size,
                rte_socket_id(),
                /* default conf */ nullptr
            );
            CHECK_NNEG(ret);
        }
        // nothing to do for hairpin queues

        // enable promiscuos mode, to allow packet
        // receiption for pkt forwarding
        ret = rte_eth_promiscuous_enable(dpdk.ingress.port_id);
        CHECK_NNEG(ret);

        // enable DPDK port
        ret = rte_eth_dev_start(dpdk.ingress.port_id);
        CHECK_NNEG(ret);
    }


    {   // configure the egress port
        struct rte_flow_error error;
        struct rte_eth_conf port_conf;

        memset(&error, 0, sizeof(error));
        memset(&port_conf, 0, sizeof(port_conf));

        ret = rte_flow_isolate(dpdk.egress.port_id, 0, &error);
        CHECK_NNEG(ret);

        ret = rte_eth_dev_configure(
            dpdk.egress.port_id,
            dpdk.nb_rxtx_queues,
            dpdk.nb_rxtx_queues,
            &port_conf
        );
        CHECK_NNEG(ret);

        for (int q = 0; q < dpdk.nb_rxtx_queues; ++q)
        {
            ret = rte_eth_rx_queue_setup(
                dpdk.egress.port_id,
                q,
                app_005_cfg::dpdk::nb_ring_rx_size,
                rte_socket_id(),
                /* default conf */ nullptr,
                dpdk.mbuf_pool
            );
            CHECK_NNEG(ret);
            ret = rte_eth_tx_queue_setup(
                dpdk.egress.port_id,
                q,
                app_005_cfg::dpdk::nb_ring_tx_size,
                rte_socket_id(),
                /* default conf */ nullptr
            );
            CHECK_NNEG(ret);
        }

        ret = rte_eth_promiscuous_enable(dpdk.egress.port_id);
        CHECK_NNEG(ret);

        ret = rte_eth_dev_start(dpdk.egress.port_id);
        CHECK_NNEG(ret);
    }

    return DOCA_SUCCESS;
}


static doca_error_t dispose_dpdk_ports_and_queues(struct app_005_cfg::dpdk &dpdk)
{
    int ret;

    // stop ports
    ret = rte_eth_dev_stop(dpdk.ingress.port_id);
    CHECK_NNEG(ret);
    ret = rte_eth_dev_stop(dpdk.egress.port_id);
    CHECK_NNEG(ret);

    // close devices
    ret = rte_eth_dev_close(dpdk.ingress.port_id);
    CHECK_NNEG(ret);
    ret = rte_eth_dev_close(dpdk.egress.port_id);
    CHECK_NNEG(ret);

    return DOCA_SUCCESS;
}

void my_doca_flow_entry_process_cb(struct doca_flow_pipe_entry *entry,
    uint16_t pipe_queue,
    enum doca_flow_entry_status status,
    enum doca_flow_entry_op op,
    void *user_ctx)
{
    (void)entry;
    (void)pipe_queue;
    (void)status;
    (void)op;
    (void)user_ctx;
    const char *status_str, *op_str;

    std::cout << "[my_doca_flow_entry_process_cb] invoked" << std::endl;
    switch (status)
    {
    case DOCA_FLOW_ENTRY_STATUS_IN_PROCESS:
        status_str = "DOCA_FLOW_ENTRY_STATUS_IN_PROCESS";
        break;
    case DOCA_FLOW_ENTRY_STATUS_SUCCESS:
        status_str = "DOCA_FLOW_ENTRY_STATUS_SUCCESS";
        break;
    case DOCA_FLOW_ENTRY_STATUS_ERROR:
        status_str = "DOCA_FLOW_ENTRY_STATUS_ERROR";
        break;
    default:
        // unreachable!
        abort();
        break;
    }
    switch (op)
    {
    case DOCA_FLOW_ENTRY_OP_ADD:
        op_str = "DOCA_FLOW_ENTRY_OP_ADD";
        break;
    case DOCA_FLOW_ENTRY_OP_DEL:
        op_str = "DOCA_FLOW_ENTRY_OP_DEL";
        break;
    case DOCA_FLOW_ENTRY_OP_UPD:
        op_str = "DOCA_FLOW_ENTRY_OP_UPD";
        break;
    case DOCA_FLOW_ENTRY_OP_AGED:
        op_str = "DOCA_FLOW_ENTRY_OP_AGED";
        break;
    default:
        // unreachable!
        abort();
        break;
    }
    std::cout << "[my_doca_flow_entry_process_cb] arguments" << std::endl;
    std::cout << "[my_doca_flow_entry_process_cb]\tstruct doca_flow_pipe_entry *entry =\t" << entry << std::endl;
    std::cout << "[my_doca_flow_entry_process_cb]\tuint16_t pipe_queue                =\t" << pipe_queue << std::endl;
    std::cout << "[my_doca_flow_entry_process_cb]\tenum doca_flow_entry_status status =\t" << status_str << std::endl;
    std::cout << "[my_doca_flow_entry_process_cb]\tenum doca_flow_entry_op op         =\t" << op_str << std::endl;
    std::cout << "[my_doca_flow_entry_process_cb]\tvoid *user_ctx                     =\t" << user_ctx << std::endl;

    std::cout << "[my_doca_flow_entry_process_cb] terminating" << std::endl;
}

static doca_error_t configure_doca_flow_library(struct app_005_cfg &cfg)
{
    doca_error_t result;
    struct doca_flow_cfg *doca_cfg = nullptr;
    struct doca_flow_resource_rss_cfg rss;

    memset(&rss, 0, sizeof(rss));

    std::cout << "Configuring DOCA Flow library..." << std::endl;

    result = doca_flow_cfg_create(&doca_cfg);
    CHECK_DERR(result);

    result = doca_flow_cfg_set_cb_entry_process(doca_cfg, my_doca_flow_entry_process_cb);
    CHECK_DERR(result);

    // application mode, Virtual Network Function,
    // with hardware steering enabled, that means
    // "-a" options passed to DPDK must be followed by
    // ",dv_flow_en=2", es.:
    //      "-a auxiliary:mlx5_core.sf.2,dv_flow_en=2"
    result = doca_flow_cfg_set_mode_args(doca_cfg, "vnf,hws");
    CHECK_DERR(result);

    // set number of pipe queues: cannot be zero or doca_flow_init fails!
    result = doca_flow_cfg_set_pipe_queues(doca_cfg, cfg.dpdk.nb_rxtx_queues);
    CHECK_DERR(result);

    cfg.dpdk.rxtx_queues.resize(cfg.dpdk.nb_rxtx_queues);
    for (int i = 0; i < cfg.dpdk.nb_rxtx_queues; ++i)
    {
        cfg.dpdk.rxtx_queues[i] = i;
    }
    rss.nr_queues = cfg.dpdk.nb_rxtx_queues;
    rss.queues_array = cfg.dpdk.rxtx_queues.data();
    result = doca_flow_cfg_set_default_rss(doca_cfg, &rss);
    CHECK_DERR(result);

    result = doca_flow_init(doca_cfg);
    CHECK_DERR(result);

    result = doca_flow_cfg_destroy(doca_cfg);
    CHECK_DERR(result);
    doca_cfg = nullptr;

    std::cout << "DOCA Flow library configured" << std::endl;

    return DOCA_SUCCESS;
}


static doca_error_t activate_doca_port(struct doca_flow_port *&port, uint16_t port_id)
{
    doca_error_t result;
    struct doca_flow_port_cfg *port_cfg = nullptr;
    char dpdk_port_num[8] = "";

    std::cout << "Starting DOCA Flow port..." << std::endl;

    result = doca_flow_port_cfg_create(&port_cfg);
    CHECK_DERR(result);

    sprintf(dpdk_port_num, "%d", port_id);
    result = doca_flow_port_cfg_set_devargs(port_cfg, dpdk_port_num);
    CHECK_DERR(result);

    result = doca_flow_port_start(port_cfg, &port);
    CHECK_DERR(result);

    result = doca_flow_port_cfg_destroy(port_cfg);
    CHECK_DERR(result);
    port_cfg = nullptr;

    std::cout << "DOCA Flow port started" << std::endl;

    return DOCA_SUCCESS;
}


static doca_error_t configure_pipe_of_ingress_port(struct app_005_cfg &cfg)
{
    constexpr int num_actions = 1;
    constexpr int entries_submission_queue = 0;
    constexpr int num_entries = 1;
    constexpr int entries_submission_timeout_us = 100000; // 100 ms

    doca_error_t result;
    struct doca_flow_pipe_cfg *pipe_cfg = nullptr;
    struct doca_flow_match match;
    struct doca_flow_actions actions, *actions_arr[num_actions] = {};
    struct doca_flow_fwd fwd, fwd_miss;
    struct doca_flow_pipe_entry *entry = nullptr;

    memset(&match, 0, sizeof(match));
    memset(&actions, 0, sizeof(actions));
    memset(&fwd, 0, sizeof(fwd));
    memset(&fwd_miss, 0, sizeof(fwd_miss));
    actions_arr[0] = &actions;

    std::cout << "Configuring DOCA Flow Pipe for ingress port..." << std::endl;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, cfg.doca.ingress.port);
    CHECK_DERR(result);

    result = doca_flow_pipe_cfg_set_name(pipe_cfg, "INGRESS_PIPE");
    CHECK_DERR(result);

    result = doca_flow_pipe_cfg_set_is_root(pipe_cfg, true);
    CHECK_DERR(result);

    result = doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);
    CHECK_DERR(result);

    result = doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, nullptr, nullptr, num_actions);
    CHECK_DERR(result);

    result = doca_flow_pipe_cfg_set_match(pipe_cfg, &match, nullptr);
    CHECK_DERR(result);

    result = doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
    CHECK_DERR(result);

    fwd.type = DOCA_FLOW_FWD_RSS;
    fwd.rss_queues = cfg.dpdk.rxtx_queues.data();
    fwd.num_of_queues = cfg.dpdk.nb_rxtx_queues;
    fwd.rss_outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_IPV6 | DOCA_FLOW_RSS_UDP | DOCA_FLOW_RSS_TCP;
    fwd_miss.type = DOCA_FLOW_FWD_DROP;
    result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, &cfg.doca.ingress.root_pipe);
    CHECK_DERR(result);

    result = doca_flow_pipe_cfg_destroy(pipe_cfg);
    CHECK_DERR(result);
    pipe_cfg = nullptr;

    result = doca_flow_pipe_add_entry(
        entries_submission_queue,
        cfg.doca.ingress.root_pipe,
        nullptr, nullptr, nullptr, nullptr,
        // DOCA_FLOW_WAIT_FOR_BATCH => invoke doca_flow_entries_process
        // to push entries to hw
        DOCA_FLOW_WAIT_FOR_BATCH /* DOCA_FLOW_NO_WAIT */,
        nullptr,
        &entry
    );
    CHECK_DERR(result);


    result = doca_flow_entries_process(
        cfg.doca.ingress.port,
        entries_submission_queue,
        entries_submission_timeout_us,
        num_entries
    );
    CHECK_DERR(result);    

    std::cout << "DOCA Flow Pipe for ingress port configured" << std::endl;

    return DOCA_SUCCESS;
}


static doca_error_t configure_pipe_of_egress_port(struct app_005_cfg &cfg)
{
    constexpr int num_actions = 1;
    constexpr int entries_submission_queue = 0;
    constexpr int num_entries = 1;
    constexpr int entries_submission_timeout_us = 10000; // 10 ms

    doca_error_t result;
    struct doca_flow_pipe_cfg *pipe_cfg = nullptr;
    struct doca_flow_match match;
    struct doca_flow_actions actions, *actions_arr[num_actions] = {};
    struct doca_flow_fwd fwd, fwd_miss;
    struct doca_flow_pipe_entry *entry = nullptr;

    memset(&match, 0, sizeof(match));
    memset(&actions, 0, sizeof(actions));
    memset(&fwd, 0, sizeof(fwd));
    memset(&fwd_miss, 0, sizeof(fwd_miss));
    actions_arr[0] = &actions;

    std::cout << "Configuring DOCA Flow Pipe for egress port..." << std::endl;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, cfg.doca.egress.port);
    CHECK_DERR(result);

    result = doca_flow_pipe_cfg_set_name(pipe_cfg, "EGRESS_PIPE");
    CHECK_DERR(result);

    result = doca_flow_pipe_cfg_set_is_root(pipe_cfg, true);
    CHECK_DERR(result);

    result = doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);
    CHECK_DERR(result);

    result = doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, nullptr, nullptr, num_actions);
    CHECK_DERR(result);

    result = doca_flow_pipe_cfg_set_match(pipe_cfg, &match, nullptr);
    CHECK_DERR(result);

    result = doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
    CHECK_DERR(result);

    fwd.type = DOCA_FLOW_FWD_RSS;
    fwd.rss_queues = cfg.dpdk.rxtx_queues.data();
    fwd.num_of_queues = cfg.dpdk.nb_rxtx_queues;
    fwd.rss_outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_IPV6 | DOCA_FLOW_RSS_UDP | DOCA_FLOW_RSS_TCP;
    fwd_miss.type = DOCA_FLOW_FWD_DROP;
    result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, &cfg.doca.egress.root_pipe);
    CHECK_DERR(result);

    result = doca_flow_pipe_cfg_destroy(pipe_cfg);
    CHECK_DERR(result);
    pipe_cfg = nullptr;

     result = doca_flow_pipe_add_entry(
        entries_submission_queue,
        cfg.doca.egress.root_pipe,
        nullptr, nullptr, nullptr, nullptr,
        // DOCA_FLOW_WAIT_FOR_BATCH => invoke doca_flow_entries_process
        // to push entries to hw
        DOCA_FLOW_WAIT_FOR_BATCH /* DOCA_FLOW_NO_WAIT */,
        nullptr,
        &entry
    );
    CHECK_DERR(result);


    result = doca_flow_entries_process(
        cfg.doca.egress.port,
        entries_submission_queue,
        entries_submission_timeout_us,
        num_entries
    );
    CHECK_DERR(result);

    std::cout << "DOCA Flow Pipe for egress port configured" << std::endl;

    return DOCA_SUCCESS;
}


static doca_error_t configure_doca_ports(struct app_005_cfg &cfg)
{
    doca_error_t result;

    // starts both DOCA ports: DOCA Ports are
    // configured on DPDK ports
    result = activate_doca_port(cfg.doca.ingress.port, cfg.dpdk.ingress.port_id);
    CHECK_DERR(result);
    result = activate_doca_port(cfg.doca.egress.port, cfg.dpdk.egress.port_id);
    CHECK_DERR(result);

    // no hairpin, so no use of doca_flow_port_pair

    return DOCA_SUCCESS;
}


static doca_error_t configure_doca(struct app_005_cfg &cfg)
{
    doca_error_t result;

    // basic configuration to enable DOCA Flow
    result = configure_doca_flow_library(cfg);
    CHECK_DERR(result);

    // configure and pair DOCA ports
    result = configure_doca_ports(cfg);
    CHECK_DERR(result);

    // configure flow pipe from ingress to egress
    result = configure_pipe_of_ingress_port(cfg);
    CHECK_DERR(result);
    // configure flow pipe from egress to ingress
    result = configure_pipe_of_egress_port(cfg);
    CHECK_DERR(result);

    return DOCA_SUCCESS;
}


static doca_error_t cleanup_doca(struct app_005_cfg &cfg)
{
    doca_error_t result;

    // destroy pipes
    std::cout << "Destroyng DOCA Flow pipes..." << std::endl;
    doca_flow_pipe_destroy(cfg.doca.ingress.root_pipe);
    doca_flow_pipe_destroy(cfg.doca.egress.root_pipe);
    std::cout << "DOCA Flow pipes destroyed" << std::endl;

    // shutdown ports
    std::cout << "Stopping DOCA Flow ports..." << std::endl;
    result = doca_flow_port_stop(cfg.doca.ingress.port);
    CHECK_DERR(result);
    result = doca_flow_port_stop(cfg.doca.egress.port);
    CHECK_DERR(result);
    std::cout << "DOCA Flow ports stopped" << std::endl;

    // cleanup DOCA Flow
    std::cout << "Disposing DOCA Flow..." << std::endl;
    doca_flow_destroy();
    std::cout << "DOCA Flow disposed" << std::endl;

    return DOCA_SUCCESS;
}


// user code will loop untill exit will be requested
static std::atomic_bool exit_request(false);

// simple signal handling, set exit flag
static void handle_exit_signal(int sig)
{
    (void)sig;
    exit_request.store(true);
}


struct worker_args
{
    struct worker_conf
    {
        bool used = false;
        struct
        {
            uint16_t port_id = -1;
            uint16_t queue_id = -1;
        } ingress;
        struct
        {
            uint16_t port_id = -1;
            uint16_t queue_id = -1;
        } egress;
    };

    std::vector<worker_conf> confs;

    worker_args(int num_threads)
    : confs(num_threads)
    {}
};


static struct worker_args get_worker_args(struct app_005_cfg &cfg)
{
    worker_args wargs(cfg.dpdk.nb_dpdk_threads);

    for (int cpu = 0; cpu < wargs.confs.size(); ++cpu)
    {
        wargs.confs[cpu].used = (cpu < cfg.dpdk.nb_rxtx_queues);
        if (wargs.confs[cpu].used)
        {
            //Ogni thread gestisce la coda col suo stesso id
            wargs.confs[cpu].ingress.port_id = cfg.dpdk.ingress.port_id;
            wargs.confs[cpu].egress.port_id = cfg.dpdk.egress.port_id;
            wargs.confs[cpu].ingress.queue_id = cfg.dpdk.rxtx_queues[cpu];
            wargs.confs[cpu].egress.queue_id = cfg.dpdk.rxtx_queues[cpu];
        }
    }

    return wargs;
}

// Static senza multi-threading, thread_local con multi-threading (per evitare race condition)
thread_local PacketAssembler assembler;
thread_local HEContext* he_ctx = nullptr;  // Inizializzato nel main, per evitare errore all'avvio
// poll for input packets from the in_* direction
// and send them to the out_* direction
inline static doca_error_t poll_interface_and_fwd(
    uint16_t in_port, uint16_t in_queue,
    uint16_t out_port, uint16_t out_queue,
    uint32_t burst_size, struct rte_mbuf ** const &mbufs
)
{
    uint16_t nb_rx = rte_eth_rx_burst(in_port, in_queue, mbufs, burst_size);

    if(nb_rx > 0){
        printf("[Thread %d] Ricevuti %u pacchetti\n", rte_lcore_index(rte_lcore_id()), nb_rx);
    }

    for (uint16_t i = 0; i < nb_rx; i++) {
        struct rte_mbuf *mbuf = mbufs[i];
        uint8_t *data = rte_pktmbuf_mtod(mbuf, uint8_t *);

        //Ethernet
        struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
        if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
            continue;

        // IPv4 
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
        if (ip->next_proto_id != IPPROTO_UDP)
            continue;

        uint16_t ip_hdr_len = (ip->version_ihl & 0x0f) * 4;

        // UDP
        struct rte_udp_hdr *udp =
            (struct rte_udp_hdr *)((uint8_t *)ip + ip_hdr_len);

        uint8_t *udp_payload = (uint8_t *)(udp + 1);
        //lunghezza dei singoli frammenti
        uint16_t udp_payload_len = rte_be_to_cpu_16(udp->dgram_len) - sizeof(struct rte_udp_hdr); 

        //Non assemblare pacchetti non destinati al receiver
        if(udp->dst_port < rte_cpu_to_be_16(9000) || udp->dst_port > rte_cpu_to_be_16(9000 + 4)){
            printf("Pacchetto con porta %u non assemblato\n", (unsigned)rte_be_to_cpu_16(udp->dst_port));
            continue;
        }

        // Devo fare cast da uint8_t a const char per come è scritto packet_assembler (in cui tengo char per semplicità)
        auto result = assembler.process_packet((const char *)udp_payload, udp_payload_len);
        if(result.complete){
            printf("[Thread %d] Pacchetto %d assemblato\n", rte_lcore_index(rte_lcore_id()), result.message_id);
            
            // Si ricrea oggetto SEAL partendo dal buffer
            std::stringstream ss(std::string(result.data.begin(), result.data.end()));
            Ciphertext ct;
            ct.load(*he_ctx->context, ss);
            
            // Somma omomorfica con una costante
            he_ctx->add_plain_number(ct, 13291);
            printf("Somma omomorfica +13291 completata\n");
            
            // Si prepara il buffer da inviare
            std::stringstream result_ss;
            ct.save(result_ss);
            std::string ciphertext_str = result_ss.str();
            printf("Ciphertext risultante: %zu bytes\n", ciphertext_str.size());
            
            // Frammentazione e invio indietro
            // Non uso la classe Message in quanto essa è fatta per l'invio con uso di socket
            uint32_t total_size = ciphertext_str.size();
            uint16_t total_chunks = (total_size + CHUNK_SIZE - 1) / CHUNK_SIZE;
            printf("Frammentazione in %u chunks\n", total_chunks);
            
            // Configuro gli indirizzi che verranno usati per inviare i singoli frammenti

            /*Non vanno modificati: nel mio test la DPU1 invia un pacchetto dal nsp0 
            al nsp1, il quale viene intercettato dalla DPU2. Gli indirizzi di destinazione,
            perciò, puntano già al nsp1 della DPU1! CAMBIO PERO' LA PORTA DI DESTINAZIONE UDP!*/
            struct rte_ether_addr src_mac = eth->src_addr;
            struct rte_ether_addr dst_mac = eth->dst_addr;
            
            uint32_t src_ip = ip->src_addr;  // IP sorgente fisso (nsp1, il sender originale)
            uint32_t dst_ip = ip->dst_addr;  // IP di destinazione del pacchetto originale (nsp0 = 192.168.28.10)
            
            uint16_t src_port = udp->src_port;
            /*Potrei lasciarla invariata, ma ho visto che se lo faccio il receiver
            intercetta i messaggi inviati dalla DPU1 prima che la DPU2 li elabori*/
            uint16_t dst_port = rte_cpu_to_be_16(8999);
            
            // Invia ogni chunk
            for (uint16_t chunk_idx = 0; chunk_idx < total_chunks; chunk_idx++) {
                // Calcola dimensione del chunk corrente
                uint32_t offset = chunk_idx * CHUNK_SIZE;
                uint16_t current_chunk_size = std::min((uint32_t)CHUNK_SIZE, total_size - offset);
                
                // Alloca mbuf per il pacchetto di risposta
                struct rte_mbuf *response_mbuf = rte_pktmbuf_alloc(mbuf->pool);
                if (!response_mbuf) {
                    printf("Errore allocazione mbuf per chunk %u\n", chunk_idx);
                    continue;
                }
                
                // Preparo il telemetry header (si trova in message.h)
                TelemetryHeader tel_hdr;
                tel_hdr.message_id = result.message_id;
                tel_hdr.total_chunks = total_chunks;
                tel_hdr.chunk_index = chunk_idx;
                tel_hdr.ciphertext_total_size = total_size;
                tel_hdr.chunk_size = current_chunk_size;
                
                // Calcolo dimensioni
                uint16_t payload_size = sizeof(TelemetryHeader) + current_chunk_size;
                uint16_t total_pkt_size = sizeof(struct rte_ether_hdr) + 
                                         sizeof(struct rte_ipv4_hdr) + 
                                         sizeof(struct rte_udp_hdr) + 
                                         payload_size;
                
                // Costruisco il pacchetto
                uint8_t *pkt_data = rte_pktmbuf_mtod(response_mbuf, uint8_t *);
                //Ogni header viene scritto nel buffer partendo dall'offset 0
                // Ethernet header
                struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)pkt_data;
                eth_hdr->src_addr = src_mac;
                eth_hdr->dst_addr = dst_mac;
                eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4); //Dice che il payload ethernet contiene un pacchetto IPv4
                
                // IP header
                struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1); //Scorro nel buffer pkt_data...
                memset(ip_hdr, 0, sizeof(struct rte_ipv4_hdr));
                ip_hdr->version_ihl = 0x45;  // IPv4
                ip_hdr->type_of_service = 0;
                ip_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + 
                                                        sizeof(struct rte_udp_hdr) + 
                                                        payload_size);
                ip_hdr->packet_id = 0;  //Non uso la frammentazione a livello IP
                ip_hdr->fragment_offset = 0;
                ip_hdr->time_to_live = 64; //Standard
                ip_hdr->next_proto_id = IPPROTO_UDP;
                ip_hdr->src_addr = src_ip;
                ip_hdr->dst_addr = dst_ip;
                ip_hdr->hdr_checksum = 0;
                ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
                
                // UDP header
                struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
                udp_hdr->src_port = src_port;
                udp_hdr->dst_port = dst_port;
                udp_hdr->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + payload_size);
                udp_hdr->dgram_cksum = 0;  // Opzionale per UDP
                
                // Payload: header telemetria + chunk dati (Come in message.cpp)
                uint8_t *payload = (uint8_t *)(udp_hdr + 1);
                memcpy(payload, &tel_hdr, sizeof(TelemetryHeader));
                memcpy(payload + sizeof(TelemetryHeader), 
                       ciphertext_str.data() + offset, 
                       current_chunk_size);
                
                // Imposta lunghezza pacchetto
                response_mbuf->data_len = total_pkt_size; //Lunghezza dati in questo mbuf
                response_mbuf->pkt_len = total_pkt_size; //Lunghezza pacchetto (che può essere distribuito su più mbuf)
                
                // Invia il pacchetto sulla porta di USCITA (out_port = P1)
                // Il pacchetto arriva su P0, viene elaborato, e esce su P1 verso DPU1:P1
                uint16_t sent = rte_eth_tx_burst(out_port, out_queue, &response_mbuf, 1);
                if (sent == 0) {
                    printf("Errore invio chunk %u\n", chunk_idx);
                    rte_pktmbuf_free(response_mbuf);
                } else {
                    printf("Chunk %u/%u inviato (payload di %u bytes)\n", 
                           chunk_idx + 1, total_chunks, current_chunk_size);
                }
            }
            
            printf("Tutti i %u chunks inviati\n", total_chunks);
        }
        
        //rte_eth_tx_burst dovrebbe occuparsi di liberare la memoria allocata per il mbuf

    }

    // Forward packets 
    uint16_t sent = 0;
    while (sent < nb_rx)
        sent += rte_eth_tx_burst(
            out_port, out_queue, &mbufs[sent], nb_rx - sent);

    return DOCA_SUCCESS;
}


static int my_dpdk_worker(void *my_dpdk_worker_arg)
{
    constexpr uint32_t burst_size = 32;
    struct rte_mbuf *mbufs[burst_size] = {};
    doca_error_t result;

    if (!my_dpdk_worker_arg)
    {
        std::cerr << "my_dpdk_worker::my_dpdk_worker = " << my_dpdk_worker_arg  << std::endl;
        abort();
    }
    const struct worker_args *wargs = (struct worker_args *)my_dpdk_worker_arg;
    // when -c/-l options are given to DPDK the core IDs are different
    // from the thread IDs (some cores might be unused)
    const auto core_id = rte_lcore_id();
    // thread ID to access thread specif parameter
    const auto worker_id = rte_lcore_index(core_id);
    // references army_dpdk_workere beautiful!
    const auto &thread_args = wargs->confs[worker_id];

    char msg[32];
    sprintf(msg, "Thread %d: %s\n", worker_id, thread_args.used ? "used" : "unused");
    std::cout << msg;
    if (!thread_args.used)
    {
        return 0;
    }

    // Inizializzazione del contesto SEAL per ogni thread separato
    he_ctx = new HEContext();

    // loop until exit is requested!
    while (!exit_request.load())
    {
        /* from ingress to egress */
        result = poll_interface_and_fwd(
            thread_args.ingress.port_id, thread_args.ingress.queue_id,
            thread_args.egress.port_id, thread_args.egress.queue_id,
            burst_size, mbufs
        );
        CHECK_DERR(result);
        /* from egress to ingress */
        result = poll_interface_and_fwd(
            thread_args.egress.port_id, thread_args.egress.queue_id,
            thread_args.ingress.port_id, thread_args.ingress.queue_id,
            burst_size, mbufs
        );
        CHECK_DERR(result);
    }

    delete he_ctx;
    he_ctx = nullptr;

    return 0;
}


int main(int argc, char *argv[])
{
    doca_error_t result;

    auto cfg = get_app_config();

    result = configure_logger(cfg);
    CHECK_DERR(result);

    // app_005_simple_l2_fwd_polling_only
    result = configure_doca_parser(cfg);
    CHECK_DERR(result);

    // invoke parser: DPDK arguments and DOCA
    // arguments are separated by '--'
    result = doca_argp_start(argc, argv);
    CHECK_DERR(result);

    // Configure DPDK ports and queues:
    //  DOCA Flow is based on DPDK
    result = configure_dpdk_ports_and_queues(cfg.dpdk);
    CHECK_DERR(result);

    // configure DOCA Flow, DOCA Ports
    // (requires DPDK preset), DOCA Flow pipes
    // (pipes are associated with ports)
    result = configure_doca(cfg);
    CHECK_DERR(result);


    auto w_args = get_worker_args(cfg);

    // set signal handler (nothing to do,
    // just avoiding crash)
    signal(SIGINT, handle_exit_signal);
    signal(SIGTERM, handle_exit_signal);

    std::cout << "Press CTRL+C to interrupt!" << std::endl;

    // launch DPDK workers
    // or better: DPDK threads have initially been created by
    //  rte_eal_init, but they have been paused and are
    //  waiting for code to execute, now this function send
    //  them the code to executed
    rte_eal_mp_remote_launch(my_dpdk_worker, &w_args, CALL_MAIN);

    // Wait for workers terminating the function
    // provided by rte_eal_mp_remote_launch
    rte_eal_mp_wait_lcore();

    std::cout << "Shutdown..." << std::endl;

    result = cleanup_doca(cfg);
    CHECK_DERR(result);

    result = dispose_dpdk_ports_and_queues(cfg.dpdk);
    CHECK_DERR(result);

    // dispose DOCA parser
    doca_argp_destroy();

    return 0;
}
