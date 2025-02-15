/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 - 2023 Mucse Corporation. */

#ifndef RNPM_REGS_H
#define RNPM_REGS_H

/*             BAR4 memory                   */
/* ------------------------------------------*/
/*	module  | size  |  start   |    end  */
/*	DMA	| 64KB	| 0_0000H  | 0_FFFFH */
/*	ETH	| 64KB	| 1_0000H  | 1_FFFFH */
/*	REG	| 64KB	| 3_0000H  | 3_FFFFH */
/*	SERDES	| 128KB	| 4_0000H  | 5_FFFFH */
/*	XLMAC1	| 64KB	| 6_0000H  | 6_FFFFH */
/*	XLMAC2	| 64KB	| 7_0000H  | 7_FFFFH */
/*	XLMAC3	| 64KB	| 8_0000H  | 8_FFFFH */
/*	XLMAC4	| 64KB	| 9_0000H  | 9_FFFFH */
/*	MSIX    | 64KB  | A_0000H  | A_FFFFH */
/*	SWITCH  | 64KB  | B_0000H  | B_FFFFH */
/*	TCAM	| 256KB	| C_0000H  | F_FFFFH */
/* ------------------------------------------*/

/* ==================== RNPM-DMA Global Registers ==================== */
#define RNPM_DMA_VERSION (0x0000)
#define RNPM_DMA_CONFIG (0x0004)
#define DMA_MAC_LOOPBACK (1 << 0)
#define DMA_SWITCH_LOOPBACK (1 << 1)
#define DMA_VEB_BYPASS (1 << 4)
#define DMA_AXI_ORDER (1 << 5)
#define DMA_RX_PADDING (1 << 8)
#define DMA_MAP_MODE(n) (n << 12)
#define DMA_RX_FRAGMENT_BYTES(n) (((n) / 16) << 16)
#define RNPM_DMA_STATUS (0x0008)
#define DMA_RING_NUM (0xff << 24)
#define RNPM_DMA_DUMY (0x000c)
/* RNPM-DMA AXI Register */
#define RNPM_DMA_AXI_EN (0x0010)
#define RX_AXI_RW_EN (0x3 << 0)
#define TX_AXI_RW_EN (0x3 << 2)
#define RNPM_DMA_AXI_STAT (0x0014)
#define RNPM_VEB_MAC_MASK_LO (0x0020)
#define RNPM_VEB_MAC_MASK_HI (0x0024)
#define RNPM_VEB_VLAN_MASK (0x0028)
#define DEBUG_PROBE_NUM (16)
#define RNPM_DMA_DEBUG_PROBE_LO_REG(n) (0x0100 + 0x08 * (n))
#define RNPM_DMA_DEBUG_PROBE_HI_REG(n) (0x0100 + 0x08 * (n))
#define DEBUG_CNT_NUM (76)
#define RNPM_DMA_DEBUG_CNT(n) (0x0200 + 0x04 * (n))
#define RNPM_DMA_STATS_DMA_TO_DMA_CHANNEL(i)                                   \
	(RNPM_DMA_DEBUG_CNT(17) + 0x04 * (i))
#define RNPM_DMA_STATS_DMA_TO_DMA_CHANNEL_0 (RNPM_DMA_DEBUG_CNT(17))
#define RNPM_DMA_STATS_DMA_TO_DMA_CHANNEL_1 (RNPM_DMA_DEBUG_CNT(18))
#define RNPM_DMA_STATS_DMA_TO_DMA_CHANNEL_2 (RNPM_DMA_DEBUG_CNT(19))
#define RNPM_DMA_STATS_DMA_TO_DMA_CHANNEL_3 (RNPM_DMA_DEBUG_CNT(20))
#define RNPM_DMA_STATS_DMA_TO_SWITCH (RNPM_DMA_DEBUG_CNT(21))
#define RNPM_DMA_STATS_MAC_TO_DMA (RNPM_DMA_DEBUG_CNT(22))
#define RNPM_DMA_STATS_SWITCH_TO_DMA (RNPM_DMA_DEBUG_CNT(23))
#define RNPM_PCI_WR_TO_HOST (RNPM_DMA_DEBUG_CNT(34))
/* DMA-ENABLE-IRQ */
#define RNPM_DMA_RX_START(idx) (0x8010 + 0x100 * (idx))
#define RNPM_DMA_RX_READY(idx) (0x8014 + 0x100 * (idx))
#define RNPM_DMA_TX_START(idx) (0x8018 + 0x100 * (idx))
// #define	RNPM_DMA_TX_START(idx)	(0x000c)
#define RNPM_DMA_TX_READY(idx) (0x801c + 0x100 * (idx))
#define RNPM_DMA_INT_STAT(idx) (0x8020 + 0x100 * (idx))
#define RNPM_DMA_INT_MASK(idx) (0x8024 + 0x100 * (idx))
#define TX_INT_MASK (1 << 1)
#define RX_INT_MASK (1 << 0)
#define RNPM_DMA_INT_CLR(idx) (0x8028 + 0x100 * (idx))
/* RX-Queue Registers */
#define RNPM_DMA_REG_RX_DESC_BUF_BASE_ADDR_HI(idx) (0x8030 + 0x100 * (idx))
#define RNPM_DMA_REG_RX_DESC_BUF_BASE_ADDR_LO(idx) (0x8034 + 0x100 * (idx))
#define RNPM_DMA_REG_RX_DESC_BUF_LEN(idx) (0x8038 + 0x100 * (idx))
#define RNPM_DMA_REG_RX_DESC_BUF_HEAD(idx) (0x803c + 0x100 * (idx))
#define RNPM_DMA_REG_RX_DESC_BUF_TAIL(idx) (0x8040 + 0x100 * (idx))
#define RNPM_DMA_REG_RX_DESC_FETCH_CTRL(idx) (0x8044 + 0x100 * (idx))
#define RNPM_DMA_REG_RX_INT_DELAY_TIMER(idx) (0x8048 + 0x100 * (idx))
#define RNPM_DMA_REG_RX_INT_DELAY_PKTCNT(idx) (0x804c + 0x100 * (idx))
#define RNPM_DMA_REG_RX_ARB_DEF_LVL(idx) (0x8050 + 0x100 * (idx))
#define PCI_DMA_REG_RX_DESC_TIMEOUT_TH(idx) (0x8054 + 0x100 * (idx))
/* TX-Queue Registers */
#define RNPM_DMA_REG_TX_DESC_BUF_BASE_ADDR_HI(idx) (0x8060 + 0x100 * (idx))
#define RNPM_DMA_REG_TX_DESC_BUF_BASE_ADDR_LO(idx) (0x8064 + 0x100 * (idx))
#define RNPM_DMA_REG_TX_DESC_BUF_LEN(idx) (0x8068 + 0x100 * (idx))
#define RNPM_DMA_REG_TX_DESC_BUF_HEAD(idx) (0x806c + 0x100 * (idx))
#define RNPM_DMA_REG_TX_DESC_BUF_TAIL(idx) (0x8070 + 0x100 * (idx))
#define RNPM_DMA_REG_TX_DESC_FETCH_CTRL(idx) (0x8074 + 0x100 * (idx))
#define RNPM_DMA_REG_TX_INT_DELAY_TIMER(idx) (0x8078 + 0x100 * (idx))
#define RNPM_DMA_REG_TX_INT_DELAY_PKTCNT(idx) (0x807c + 0x100 * (idx))
#define RNPM_DMA_REG_TX_ARB_DEF_LVL(idx) (0x8080 + 0x100 * (idx))
#define RNPM_DMA_REG_TX_FLOW_CTRL_TH(idx) (0x8084 + 0x100 * (idx))
#define RNPM_DMA_REG_TX_FLOW_CTRL_TM(idx) (0x8088 + 0x100 * (idx))
/* VEB Registers */
#define VEB_TBL_CNTS (64)
#define RNPM_DMA_PORT_VBE_MAC_LO_TBL(port, vf)                                 \
	(0x80A0 + 4 * (port) + 0x100 * (vf))
#define RNPM_DMA_PORT_VBE_MAC_HI_TBL(port, vf)                                 \
	(0x80B0 + 4 * (port) + 0x100 * (vf))
#define RNPM_DMA_PORT_VEB_VID_TBL(port, vf) (0x80C0 + 4 * (port) + 0x100 * (vf))
#define RNPM_DMA_PORT_VEB_VF_RING_TBL(port, vf)                                \
	(0x80D0 + 4 * (port) + 0x100 * (vf))
/* ================================================================== */

/* ==================== RNPM-ETH Global Registers ==================== */
#define RNPM_ETH_BASE (0x10000)

#define ETH_ERR_SCTP (1 << 4)
#define ETH_ERR_L4 (1 << 3)
#define ETH_ERR_L3 (1 << 2)
#define ETH_ERR_PKT_LEN_ERR (1 << 1)
#define ETH_ERR_HDR_LEN_ERR (1 << 0)
#define ETH_IGNORE_ALL_ERR                                                     \
	(ETH_ERR_SCTP | ETH_ERR_L4 | ETH_ERR_L3 | ETH_ERR_PKT_LEN_ERR |        \
	 ETH_ERR_HDR_LEN_ERR)
#define VM_DMAC_TBL_SZ (128)
#define RNPM_ETH_ENABLE_RSS_ONLY (0x3f30001)
#define RNPM_ETH_DISABLE_RSS (0)

#define RNPM_ETH_TX_PROGFULL_THRESH_PORT(n)                                    \
	(RNPM_ETH_BASE + 0x0060 + 0x08 * (n))
#define RNPM_ETH_TX_PROGEMPTY_THRESH_PORT(n)                                   \
	(RNPM_ETH_BASE + 0x0064 + 0x08 * (n))

#define RNPM_ETH_EMAC_DMA_PROFULL_THRESH (RNPM_ETH_BASE + 0x0080)
#define RNPM_ETH_EMAC_DMA_PROEMPTY_THRESH (RNPM_ETH_BASE + 0x0084)
#define RNPM_ETH_EMAC_SW_PROFULL_THRESH (RNPM_ETH_BASE + 0x0088)
#define RNPM_ETH_EMAC_SW_PROEMPTY_THRESH (RNPM_ETH_BASE + 0x008c)
#define RNPM_ETH_EMAC_BMC_TX_PROFULL_THRESH (RNPM_ETH_BASE + 0x0090)
#define RNPM_ETH_EMAC_BMC_TX_PROEMPTY_THRESH (RNPM_ETH_BASE + 0x0094)

#define RNPM_ETH_CNT_PKT_EMAC_TX(n) (RNPM_ETH_BASE + 0x00a0 + 0x04 * (n))
#define RNPM_ETH_CNT_PKT_PECL_TX(n) (RNPM_ETH_BASE + 0x00b0 + 0x04 * (n))
#define RNPM_ETH_STATUS_TX_FLOWCTRL(n) (RNPM_ETH_BASE + 0x00c0 + 0x04 * (n))
#define RNPM_ETH_VERSION_FLOWWCTRL (RNPM_ETH_BASE + 0x00d0)
#define RNPM_ETH_CFG_ETH_MAC (RNPM_ETH_BASE + 0x00d4)

#define RNPM_ETH_SCA_TX_CS(port) (RNPM_ETH_BASE + 0x0100 + 0x08 * (port))
#define RNPM_ETH_SCA_TX_NS(port) (RNPM_ETH_BASE + 0x0104 + 0x08 * (port))
#define RNPM_ETH_TXTRANS_CS(port) (RNPM_ETH_BASE + 0x0120 + 0x08 * (port))
#define RNPM_ETH_TXTRANS_NS(port) (RNPM_ETH_BASE + 0x0124 + 0x08 * (port))

#define RNPM_ETH_1TO4_INST0_IN_PKTS (RNPM_ETH_BASE + 0x0200)
#define RNPM_ETH_1TO4_INST1_IN_PKTS (RNPM_ETH_BASE + 0x0204)
#define RNPM_ETH_1TO4_INST2_IN_PKTS (RNPM_ETH_BASE + 0x0208)
#define RNPM_ETH_1TO4_INST3_IN_PKTS (RNPM_ETH_BASE + 0x020c)
#define RNPM_ETH_IN_0_TX_PKT_NUM(port) (RNPM_ETH_BASE + 0x0210 + 0x10 * (port))
#define RNPM_ETH_IN_1_TX_PKT_NUM(port) (RNPM_ETH_BASE + 0x0214 + 0x10 * (port))
#define RNPM_ETH_IN_2_TX_PKT_NUM(port) (RNPM_ETH_BASE + 0x0218 + 0x10 * (port))
#define RNPM_ETH_IN_3_TX_PKT_NUM(port) (RNPM_ETH_BASE + 0x021c + 0x10 * (port))

#define RNPM_ETH_EMAC_TX_TO_PHY_PKTS(port) (RNPM_ETH_BASE + 0x0250 + 4 * (port))
#define RNPM_ETH_TXTRANS_PTP_PKT_NUM(port) (RNPM_ETH_BASE + 0x0260 + 4 * (port))

#define RNPM_ETH_TX_DEBUG(n) (RNPM_ETH_BASE + 0x0300 + 0x04 * (n))

#define RNPM_ETH_TX_DEBUG_PORT0_SOP (RNPM_ETH_BASE + 0x0300)
#define RNPM_ETH_TX_DEBUG_PORT0_EOP (RNPM_ETH_BASE + 0x0304)

#define RNPM_ETH_TX_DEBUG_PORT1_SOP (RNPM_ETH_BASE + 0x0308)
#define RNPM_ETH_TX_DEBUG_PORT1_EOP (RNPM_ETH_BASE + 0x030c)

#define RNPM_ETH_TX_DEBUG_PORT2_SOP (RNPM_ETH_BASE + 0x0310)
#define RNPM_ETH_TX_DEBUG_PORT2_EOP (RNPM_ETH_BASE + 0x0314)

#define RNPM_ETH_TX_DEBUG_PORT3_SOP (RNPM_ETH_BASE + 0x0318)
#define RNPM_ETH_TX_DEBUG_PORT3_EOP (RNPM_ETH_BASE + 0x031c)

#define RNPM_ETH_TX_DEBUG_EMPTY (RNPM_ETH_BASE + 0x0334)
#define RNPM_ETH_TX_DEBUG_PROG_FULL (RNPM_ETH_BASE + 0x0338)
#define RNPM_ETH_TX_DEBUG_FULL (RNPM_ETH_BASE + 0x033c)

/* 1588 */
#define RNPM_ETH_PTP_TX_STATUS(n) (RNPM_ETH_BASE + 0x0400 + 0x14 * (n))
#define RNPM_ETH_PTP_TX_HTIMES(n) (RNPM_ETH_BASE + 0x0404 + 0x14 * (n))
#define RNPM_ETH_PTP_TX_LTIMES(n) (RNPM_ETH_BASE + 0x0408 + 0x14 * (n))
#define RNPM_ETH_PTP_TX_TSVALUE_STATUS(n) (RNPM_ETH_BASE + 0x040c + 0x14 * (n))
#define RNPM_ETH_PTP_TX_CLEAR(n) (RNPM_ETH_BASE + 0x0410 + 0x14 * (n))

#define RNPM_ETH_MAC_SPEED_PORT(n) (RNPM_ETH_BASE + 0x0450 + 0x04 * (n))
#define RNPM_ETH_MAC_LOOPBACK_MODE_PORT(n) (RNPM_ETH_BASE + 0x0460 + 0x04 * (n))
#define RNPM_ETH_EXCEPT_DROP_PROC (RNPM_ETH_BASE + 0x0470)

#define RNPM_ETH_IPP (RNPM_ETH_BASE + 0x8000)
#define RNPM_ETH_BYPASS (RNPM_ETH_BASE + 0x8000)
#define RNPM_ETH_TUNNEL_MOD (RNPM_ETH_BASE + 0x8004)
#define INNER_L4_BIT BIT(6)
#define PKT_LEN_ERR (2)
#define HDR_LEN_ERR (1)
#define RNPM_ETH_LOOPBACK_EN (RNPM_ETH_BASE + 0x8008)
#define RNPM_FIFO_CTRL_MODE (RNPM_ETH_BASE + 0x800c)
#define RNPM_ETH_VXLAN_PORT (RNPM_ETH_BASE + 0x8010)
#define RNPM_ETH_NVGRE_PORT (RNPM_ETH_BASE + 0x8014)
#define RNPM_ETH_RDMA_PORT (RNPM_ETH_BASE + 0x8018)
#define RNPM_HOST_FILTER_EN (RNPM_ETH_BASE + 0x801c)
#define RNPM_MNG_FILTER_EN (RNPM_ETH_BASE + 0x8020)
#define RNPM_ETH_TCAM_EN (RNPM_ETH_BASE + 0x8024)
#define RNPM_CONGEST_DROP_EN (RNPM_ETH_BASE + 0x8028)
#define RNPM_REDIR_EN (RNPM_ETH_BASE + 0x8030)
#define RNPM_ETH_SCTP_CHECKSUM_EN (RNPM_ETH_BASE + 0x8038)
#define RNPM_ETH_ARP_FUNC_EN (RNPM_ETH_BASE + 0x803c)
#define RNPM_ETH_VLAN_VME_REG(n) (RNPM_ETH_BASE + 0x8040 + 0x04 * (n))
#define RNPM_ETH_CVLAN_RM_EN (RNPM_ETH_BASE + 0x8050)
#define RNPM_ETH_VLAN_RM_TYPE (RNPM_ETH_BASE + 0x8054)
#define RNPM_ETH_WRAP_FIELD_TYPE (RNPM_ETH_BASE + 0x805c)
#define RNPM_ETH_ERR_MASK_VECTOR (RNPM_ETH_BASE + 0x8060)
#define RNPM_ETH_DEFAULT_RX_RING (RNPM_ETH_BASE + 0x806c)

#define DROP_ALL_THRESH (2046) // drop all rx
#define RECEIVE_ALL_THRESH (0x270) // receive all rx

#define RNPM_ETH_RX_PROGFULL_THRESH_PORT(n)                                    \
	(RNPM_ETH_BASE + 0x8070 + 0x08 * (n))
#define RNPM_ETH_RX_PROGEMPTY_THRESH_PORT(n)                                   \
	(RNPM_ETH_BASE + 0x8074 + 0x08 * (n))

#define RNPM_ETH_EMAC_GAT_PROGFULL_THRESH (RNPM_ETH_BASE + 0x8090)
#define RNPM_ETH_EMAC_GAT_PROGEMPTY_THRESH (RNPM_ETH_BASE + 0x8094)
#define RNPM_ETH_EMAC_PARSE_PROGFULL_THRESH (RNPM_ETH_BASE + 0x8098)
#define RNPM_ETH_EMAC_PARSE_PROGEMPTY_THRESH (RNPM_ETH_BASE + 0x809c)
#define RNPM_ETH_FC_PROGFULL_THRESH (RNPM_ETH_BASE + 0x80a0)
#define RNPM_ETH_FC_PROGEMPTY_THRESH (RNPM_ETH_BASE + 0x80a4)
#define RNPM_ETH_DIS_PROGFULL_THRESH (RNPM_ETH_BASE + 0x80a8)
#define RNPM_ETH_DIS_PROGEMPTY_THRESH (RNPM_ETH_BASE + 0x80ac)
#define RNPM_ETH_COV_PROGFULL_THRESH (RNPM_ETH_BASE + 0x80b0)
#define RNPM_ETH_COV_PROGEMPTY_THRESH (RNPM_ETH_BASE + 0x80b4)
#define RNPM_ETH_BMC_RX_PROGFULL_THRESH (RNPM_ETH_BASE + 0x80b8)
#define RNPM_ETH_BMC_RX_PROGEMPTY_THRESH (RNPM_ETH_BASE + 0x80bc)
#define RNPM_ETH_HIGH_WATER(n) (RNPM_ETH_BASE + 0x80c0 + n * (0x08))
#define RNPM_ETH_LOW_WATER(n) (RNPM_ETH_BASE + 0x80c4 + n * (0x08))
#define RNPM_ETH_DEFAULT_RX_MIN_LEN (RNPM_ETH_BASE + 0x80f0)
#define RNPM_ETH_DEFAULT_RX_MAX_LEN (RNPM_ETH_BASE + 0x80f4)
#define RNPM_ETH_PTP_EVENT_PORT (RNPM_ETH_BASE + 0x80f8)
#define RNPM_ETH_PTP_GENER_PORT_REG (RNPM_ETH_BASE + 0x80fc)
#define RNPM_ETH_RX_TRANS_CS_PORT(n) (RNPM_ETH_BASE + 0x8100 + 0x08 * (n))
#define RNPM_ETH_RX_TRANS_NS_PORT(n) (RNPM_ETH_BASE + 0x8104 + 0x08 * (n))

#define RNPM_ETH_GAT_RX_CS (RNPM_ETH_BASE + 0x8120)
#define RNPM_ETH_GAT_RX_NS (RNPM_ETH_BASE + 0x8124)
#define RNPM_ETH_EMAC_PIP_CS (RNPM_ETH_BASE + 0x8128)
#define RNPM_ETH_EMAC_PIP_NS (RNPM_ETH_BASE + 0x812c)
#define RNPM_ETH_EMAC_FC_CS (RNPM_ETH_BASE + 0x8138)
#define RNPM_ETH_EMAC_FC_NS (RNPM_ETH_BASE + 0x813c)
#define RNPM_ETH_EMAC_DIS_CS (RNPM_ETH_BASE + 0x8140)
#define RNPM_ETH_EMAC_DIS_NS (RNPM_ETH_BASE + 0x8144)
#define RNPM_ETH_HOST_L2_FILTER_CS (RNPM_ETH_BASE + 0x8150)
#define RNPM_ETH_HOST_L2_FILTER_NS (RNPM_ETH_BASE + 0x8154)
#define RNPM_ETH_EMAC_DECAP_CS (RNPM_ETH_BASE + 0x8158)
#define RNPM_ETH_EMAC_DECAP_NS (RNPM_ETH_BASE + 0x815c)

#define RNPM_ETH_PFC_CONFIG_PROT(n) (RNPM_ETH_BASE + 0x8180 + n * (0x04))

#define RNPM_ETH_RX_PKT_NUM(port) (RNPM_ETH_BASE + 0x8220 + 0x04 * (port))
#define RNPM_ETH_RX_DROP_PKT_NUM(port) (RNPM_ETH_BASE + 0x8230 + 0x04 * (port))
#define RNPM_ETH_TOTAL_GAT_RX_PKT_NUM (RNPM_ETH_BASE + 0x8240)
#define RNPM_ETH_PKT_ARP_REQ_NUM (RNPM_ETH_BASE + 0x8250)
#define RNPM_ETH_PKT_ARP_RESPONSE_NUM (RNPM_ETH_BASE + 0x8254)
#define RNPM_ETH_ICMP_NUM (RNPM_ETH_BASE + 0x8258)
#define RNPM_ETH_PKT_UDP_NUM (RNPM_ETH_BASE + 0x825c)
#define RNPM_ETH_PKT_TCP_NUM (RNPM_ETH_BASE + 0x8260)
#define RNPM_ETH_PKT_ESP_NUM (RNPM_ETH_BASE + 0x8264)
#define RNPM_ETH_PKT_GRE_NUM (RNPM_ETH_BASE + 0x8268)
#define RNPM_ETH_PKT_SCTP_NUM (RNPM_ETH_BASE + 0x826c)
#define RNPM_ETH_PKT_TCPSYN_NUM (RNPM_ETH_BASE + 0x8270)
#define RNPM_ETH_PKT_VXLAN_NUM (RNPM_ETH_BASE + 0x8274)
#define RNPM_ETH_PKT_NVGRE_NUM (RNPM_ETH_BASE + 0x8278)
#define RNPM_ETH_PKT_FRAGMENT_NUM (RNPM_ETH_BASE + 0x827c)
#define RNPM_ETH_PKT_LAYER1_VLAN_NUM (RNPM_ETH_BASE + 0x8280)
#define RNPM_ETH_PKT_LAYER2_VLAN_NUM (RNPM_ETH_BASE + 0x8284)
#define RNPM_ETH_PKT_IPV4_NUM (RNPM_ETH_BASE + 0x8288)
#define RNPM_ETH_PKT_IPV6_NUM (RNPM_ETH_BASE + 0x828c)
#define RNPM_ETH_PKT_INGRESS_NUM (RNPM_ETH_BASE + 0x8290)
#define RNPM_ETH_PKT_EGRESS_NUM (RNPM_ETH_BASE + 0x8294)
#define RNPM_ETH_PKT_IP_HDR_LEN_ERR_NUM (RNPM_ETH_BASE + 0x8298)
#define RNPM_ETH_PKT_IP_PKT_LEN_ERR_NUM (RNPM_ETH_BASE + 0x829c)
#define RNPM_ETH_PKT_L3_HDR_CHK_ERR_NUM (RNPM_ETH_BASE + 0x82a0)
#define RNPM_ETH_PKT_L4_HDR_CHK_ERR_NUM (RNPM_ETH_BASE + 0x82a4)
#define RNPM_ETH_PKT_SCTP_CHK_ERR_NUM (RNPM_ETH_BASE + 0x82a8)
#define RNPM_ETH_PKT_VLAN_ERR_NUM (RNPM_ETH_BASE + 0x82ac)
#define RNPM_ETH_PKT_RDMA_NUM (RNPM_ETH_BASE + 0x82b0)
#define RNPM_ETH_PKT_ARP_AUTO_RESPONSE_NUM (RNPM_ETH_BASE + 0x82b4)
#define RNPM_ETH_PKT_ICMPV6_NUM (RNPM_ETH_BASE + 0x82b8)
#define RNPM_ETH_PKT_IPV6_EXTEND_NUM (RNPM_ETH_BASE + 0x82bc)
#define RNPM_ETH_PKT_802_3_NUM (RNPM_ETH_BASE + 0x82c0)
#define RNPM_ETH_PKT_EXCEPT_SHORT_NUM (RNPM_ETH_BASE + 0x82c4)
#define RNPM_ETH_PKT_PTP_NUM (RNPM_ETH_BASE + 0x82c8)
#define RNPM_ETH_DECAP_PKT_IN_NUM (RNPM_ETH_BASE + 0x82d0)
#define RNPM_ETH_DECAP_PKT_OUT_NUM (RNPM_ETH_BASE + 0x82d4)
#define RNPM_ETH_DECAP_DMAC_OUT_NUM (RNPM_ETH_BASE + 0x82d8)
#define RNPM_ETH_DECAP_BMC_OUT_NUM (RNPM_ETH_BASE + 0x82dc)
#define RNPM_ETH_DECAP_SW_OUT_NUM (RNPM_ETH_BASE + 0x82e0)
#define RNPM_ETH_DECAP_MIRROR_OUT_NUM (RNPM_ETH_BASE + 0x82e4)
#define RNPM_ETH_DECAP_PKT_DROP_NUM(port)                                      \
	(RNPM_ETH_BASE + 0x82e8 + 0x04 * (port))
#define RNPM_ETH_INVALID_DROP_PKTS RNPM_ETH_DECAP_PKT_DROP_NUM(0)
#define RNPM_ETH_FILTER_DROP_PKTS RNPM_ETH_DECAP_PKT_DROP_NUM(1)
#define RNPM_ETH_DECAP_DMAC_DROP_NUM (RNPM_ETH_BASE + 0x82f0)
#define RNPM_ETH_DECAP_BMC_DROP_NUM (RNPM_ETH_BASE + 0x82f4)
#define RNPM_ETH_DECAP_SWITCH_DROP_NUM (RNPM_ETH_BASE + 0x82f8)
#define RNPM_ETH_DECAP_RM_VLAN_NUM (RNPM_ETH_BASE + 0x82fc)
#define RNPM_ETH_RX_FC_PKT_IN_NUM (RNPM_ETH_BASE + 0x8300)
#define RNPM_ETH_RX_FC_PKT_OUT_NUM (RNPM_ETH_BASE + 0x8304)
#define RNPM_ETH_RX_FC_PKT_DROP0_NUM (RNPM_ETH_BASE + 0x8308)
#define RNPM_ETH_RX_FC_PKT_DROP1_NUM (RNPM_ETH_BASE + 0x830c)
#define RNPM_ETH_RING_FC_STATUS0 (RNPM_ETH_BASE + 0x8310)
#define RNPM_ETH_RING_FC_STATUS1 (RNPM_ETH_BASE + 0x8314)
#define RNPM_ETH_RING_FC_STATUS2 (RNPM_ETH_BASE + 0x8318)
#define RNPM_ETH_RING_FC_STATUS3 (RNPM_ETH_BASE + 0x831c)
#define RNPM_ETH_RX_DEBUG(n) (RNPM_ETH_BASE + 0x8400 + 0x04 * (n))
#define RNPM_ETH_RX_FC_DEBUG0_NUM RNPM_ETH_RX_DEBUG(0)
#define RNPM_ETH_RX_FC_DEBUG1_NUM RNPM_ETH_RX_DEBUG(1)
#define RNPM_ETH_RX_DIS_DEBUG0_NUM RNPM_ETH_RX_DEBUG(2)
#define RNPM_ETH_RX_DIS_DEBUG1_NUM RNPM_ETH_RX_DEBUG(3)
#define RNPM_ETH_HOST_L2_DROP_PKTS RNPM_ETH_RX_DEBUG(4)
#define RNPM_ETH_REDIR_INPUT_MATCH_DROP_PKTS RNPM_ETH_RX_DEBUG(5)
#define RNPM_ETH_ETYPE_DROP_PKTS RNPM_ETH_RX_DEBUG(6)
#define RNPM_ETH_TCP_SYN_DROP_PKTS RNPM_ETH_RX_DEBUG(7)
#define RNPM_ETH_REDIR_TUPLE5_DROP_PKTS RNPM_ETH_RX_DEBUG(8)
#define RNPM_ETH_REDIR_TCAM_DROP_PKTS RNPM_ETH_RX_DEBUG(9)
#define RNPM_ETH_VMARK_TC(n) (RNPM_ETH_BASE + 0x8500 + 0x04 * (n))
#define RNPM_RING_FC_ENABLE (RNPM_ETH_BASE + 0x8520)
#define RNPM_SELECT_RING_EN(n) (RNPM_ETH_BASE + 0x8524 + (0x4 * n))
#define RNPM_TC_FC_SW_EN (RNPM_ETH_BASE + 0x8534)

#define RNPM_ETH_LOCAL_DIP(n) (RNPM_ETH_BASE + 0x8600 + 0x04 * (n))
#define RNPM_ETH_LOCAL_DMAC_H(n) (RNPM_ETH_BASE + 0x8700 + 0x04 * (n))
#define RNPM_ETH_LOCAL_DMAC_L(n) (RNPM_ETH_BASE + 0x8800 + 0x04 * (n))
/* Rx Ring Flow Control */
/* tc 8 */
#define RNPM_RXTRANS_RX_PKTS(port) (RNPM_ETH_BASE + 0x8900 + 0x40 * (port))
#define RNPM_RXTRANS_DROP_PKTS(port) (RNPM_ETH_BASE + 0x8904 + 0x40 * (port))
#define RNPM_RXTRANS_WDT_ERR_PKTS(port) (RNPM_ETH_BASE + 0x8908 + 0x40 * (port))
#define RNPM_RXTRANS_CODE_ERR_PKTS(port)                                       \
	(RNPM_ETH_BASE + 0x890c + 0x40 * (port))
#define RNPM_RXTRANS_CRC_ERR_PKTS(port) (RNPM_ETH_BASE + 0x8910 + 0x40 * (port))
#define RNPM_RXTRANS_SLEN_ERR_PKTS(port)                                       \
	(RNPM_ETH_BASE + 0x8914 + 0x40 * (port))
#define RNPM_RXTRANS_GLEN_ERR_PKTS(port)                                       \
	(RNPM_ETH_BASE + 0x8918 + 0x40 * (port))
#define RNPM_RXTRANS_IPH_ERR_PKTS(port) (RNPM_ETH_BASE + 0x891c + 0x40 * (port))
#define RNPM_RXTRANS_CSUM_ERR_PKTS(port)                                       \
	(RNPM_ETH_BASE + 0x8920 + 0x40 * (port))
#define RNPM_RXTRANS_LEN_ERR_PKTS(port) (RNPM_ETH_BASE + 0x8924 + 0x40 * (port))
#define RNPM_RXTRANS_CUT_ERR_PKTS(port) (RNPM_ETH_BASE + 0x8928 + 0x40 * (port))
#define RNPM_RXTRANS_EXCEPT_BYTES(port) (RNPM_ETH_BASE + 0x892c + 0x40 * (port))
#define RNPM_RXTRANS_G1600_BYTES_PKTS(port)                                    \
	(RNPM_ETH_BASE + 0x8930 + 0x40 * (port))

#define RNPM_RX_RING_MAXRATE(n) (RNPM_ETH_BASE + 0x8a00 + (0x4 * n))
// emac_mng_filter no used in host
#define RNPM_ETH_RX_PROGFULL_RTRN(n) (RNPM_ETH_BASE + 0x8c00 + 0x04 * (n))
#define RNPM_ETH_CNT_PKT_EMAC_RX(n) (RNPM_ETH_BASE + 0x8c10 + 0x04 * (n))
#define RNPM_ETH_CNT_PKT_PECL_RX(n) (RNPM_ETH_BASE + 0x8c20 + 0x04 * (n))
#define RNPM_ETH_STATUS_RX_FLOWCTRL(n) (RNPM_ETH_BASE + 0x8c30 + 0x04 * (n))

#define RNPM_ETH_DMAC_FCTRL (RNPM_ETH_BASE + 0x9110)
#define RNPM_ETH_DMAC_MCSTCTRL (RNPM_ETH_BASE + 0x9114)
#define RNPM_MCSTCTRL_MULTICASE_TBL_EN (1 << 2)
#define RNPM_MCSTCTRL_UNICASE_TBL_EN (1 << 3)
#define RNPM_MCSTCTRL_DMAC_47 (0x00)
#define RNPM_MCSTCTRL_DMAC_46 (0x01)
#define RNPM_MCSTCTRL_DMAC_45 (0x02)
#define RNPM_MCSTCTRL_DMAC_43 (0x03)
#define RNPM_ETH_VLAN_FILTER_ENABLE (RNPM_ETH_BASE + 0x9118)

#define RNPM_ETH_INPORT_POLICY_VAL (RNPM_ETH_BASE + 0x91d0)
#define RNPM_ETH_INPORT_POLICY_REG(n) (RNPM_ETH_BASE + 0x91e0 + 0x04 * (n))
#define ETH_LAYER2_NUM (16)
#define RNPM_ETH_LAYER2_ETQF(n) (RNPM_ETH_BASE + 0x9200 + 0x04 * (n))
#define RNPM_ETH_LAYER2_ETQS(n) (RNPM_ETH_BASE + 0x9240 + 0x04 * (n))
#define RNPM_ETH_LAYER2_ETQS_DEFAULT (RNPM_ETH_BASE + 0x9280)
#define RNPM_ETH_ETQF_DEFAULT (RNPM_ETH_BASE + 0x9284)
#define RNPM_ETH_SYNQF (RNPM_ETH_BASE + 0x9290)
#define RNPM_ETH_SYNQF_PRIORITY (RNPM_ETH_BASE + 0x9294)
/*
 * [3:0]:
 * 4'b0000: RSS disable
 * 4'b0001: RSS only
 * 4'b0100: DCB and RSS--8 * 16
 * 4'b1010: POOLS and RSS--32 * 4
 * [3] :virtual enable
 * [16]:ipv4_hash_tcp_enable
 * [17]:ipv4_hash_enable
 * [20]:ipv6_hash_enable
 * [21]:ipv6_hash_tcp_enable
 * [22]:ipv4_hash_udp_enable
 * [23]:ipv6_hash_udp_enable
 * [24]:ipv4_hash_sctp_enable
 * [25]:ipv6_hash_sctp_enable
 */
#define RNPM_ETH_RSS_CONTROL (RNPM_ETH_BASE + 0x92a0)
#define RNPM_MRQC_IOV_EN (RNPM_ETH_BASE + 0x92a0)
#define RNPM_IOV_ENABLED (1 << 3)
#define RNPM_ETH_RSS_KEY (RNPM_ETH_BASE + 0x92d0)

#define RNPM_ETH_RAR_RL(n) (RNPM_ETH_BASE + 0xa000 + 0x04 * n)
#define RNPM_ETH_RAR_RH(n) (RNPM_ETH_BASE + 0xa400 + 0x04 * n)
#define RNPM_ETH_UTA(n) (RNPM_ETH_BASE + 0xa800 + 0x04 * n)
#define RNPM_ETH_MUTICAST_HASH_TABLE(n) (RNPM_ETH_BASE + 0xac00 + 0x04 * n)
#define RNPM_MTA(n) RNPM_ETH_MUTICAST_HASH_TABLE(n)

#define RNPM_ETH_VLAN_FILTER_TABLE(n) (RNPM_ETH_BASE + 0xb000 + 0x04 * (n))
#define RNPM_VFTA RNPM_ETH_VLAN_FILTER_TABLE
#define RNPM_FCTRL_MULTICASE_BYPASS (1 << 8)
#define RNPM_FCTRL_UNICASE_BYPASS (1 << 9)
#define RNPM_FCTRL_BROADCASE_BYPASS (1 << 10)

#define RNPM_ETH_ETYPE_TABLE(n) (RNPM_ETH_BASE + 0xb300 + 0x04 * (n))
#define RNPM_VM_DMAC_MPSAR_RING(entry) (RNPM_ETH_BASE + 0xb400 + (4 * (entry)))
#define RNPM_VLVF(idx) (RNPM_ETH_BASE + 0xb600 + 4 * (idx))
#define RNPM_VLVFB(idx) (RNPM_ETH_BASE + 0xb700 + 4 * (idx))
#define RNPM_VM_TUNNEL_PFVLVF_L(n) (RNPM_ETH_BASE + 0xb800 + 0x04 * (n))
#define RNPM_VM_TUNNEL_PFVLVF_H(n) (RNPM_ETH_BASE + 0xb900 + 0x04 * (n))
/* 5 tuple */
#define ETH_TUPLE5_NUM (128)
#define RNPM_ETH_TUPLE5_SAQF(n) (RNPM_ETH_BASE + 0xc000 + 0x04 * (n))
#define RNPM_ETH_TUPLE5_DAQF(n) (RNPM_ETH_BASE + 0xc400 + 0x04 * (n))
#define RNPM_ETH_TUPLE5_SDPQF(n) (RNPM_ETH_BASE + 0xc800 + 0x04 * (n))
#define RNPM_ETH_TUPLE5_FTQF(n) (RNPM_ETH_BASE + 0xcc00 + 0x04 * (n))
#define RNPM_ETH_TUPLE5_POLICY(n) (RNPM_ETH_BASE + 0xd000 + 0x04 * (n))
#define RNPM_ETH_RSS_INDIR_TBL(p, n)                                           \
	(RNPM_ETH_BASE + 0xe000 + 0x04 * (n) + 0x200 * (p))
/* tc is 8 */
#define RNPM_ETH_TC_IPH_OFFSET_TABLE(n) (RNPM_ETH_BASE + 0xe800 + 0x04 * (n))
#define RNPM_ETH_TC_VLAN_OFFSET_TABLE(n) (RNPM_ETH_BASE + 0xe820 + 0x04 * (n))
/* port is 4 */
#define RNPM_ETH_TC_PORT_OFFSET_TABLE(n) (RNPM_ETH_BASE + 0xe840 + 0x04 * (n))
#define RNPM_REDIR_RING_MASK (RNPM_ETH_BASE + 0xe860)
/* uv3p only */
#define RNPM_ETH_RSS_MODE (0x6fe00)
#define RNPM_ETH_RSS_INDIR_TBL_UV3P(n) (0x6ff00 + 0x04 * (n))

/* ================================================================== */

/* ==================== RNPM-REG Global Registers ==================== */
#define RNPM_COMM_REG0 (0x30000)
#define RNPM_TOP_NIC_VERSION (RNPM_COMM_REG0 + 0x0000)
#define RNPM_TOP_NIC_CONFIG (RNPM_COMM_REG0 + 0x0004)
#define RNPM_TOP_NIC_STAT (RNPM_COMM_REG0 + 0x0008)
#define RNPM_TOP_NIC_DUMMY (RNPM_COMM_REG0 + 0x000c)
#define RNPM_TOP_NIC_REST_N (RNPM_COMM_REG0 + 0x0010)
#define NIC_RESET (0)
/* dma top */
#define RNPM_TOP_DMA_MEM_SLP (RNPM_COMM_REG0 + 0x4004)
#define RNPM_TOP_DMA_MEM_SD (RNPM_COMM_REG0 + 0x4008)
/* eth top */
#define RNPM_TOP_ETH_TIMESTAMP_SEL (RNPM_COMM_REG0 + 0x8010)
#define RNPM_TOP_ETH_MAC_CLK_SEL (RNPM_COMM_REG0 + 0x8014)
#define RNPM_TOP_ETH_INF_ETH_STATUS (RNPM_COMM_REG0 + 0x8018)
#define RNPM_TOP_ETH_BUG_40G_PATCH (RNPM_COMM_REG0 + 0x801c)
#define RNPM_TOP_ETH_PWR_PORT_NUM (4)
#define RNPM_TOP_ETH_PWR_CLAMP_CTRL_PORT(n)                                    \
	(RNPM_COMM_REG0 + 0x8020 + 0xc * (n))
#define RNPM_TOP_ETH_PWR_ISOLATE_PORT(n) (RNPM_COMM_REG0 + 0x8024 + 0xc * (n))
#define RNPM_TOP_ETH_PWR_DOWN_PORT(n) (RNPM_COMM_REG0 + 0x8028 + 0xc * (n))
#define RNPM_TOP_ETH_TCAM_CONFIG_ENABLE (RNPM_COMM_REG0 + 0x8050)
#define RNPM_TOP_ETH_SLIP (RNPM_COMM_REG0 + 0x8060)
#define RNPM_TOP_ETH_SHUT_DOWN (RNPM_COMM_REG0 + 0x8064)
#define RNPM_TOP_ETH_OVS_SLIP (RNPM_COMM_REG0 + 0x8068)
#define RNPM_TOP_ETH_OVS_SHUT_DOWN (RNPM_COMM_REG0 + 0x806c)
/* ?? */
#define RNPM_FC_PORT_ENABLE (RNPM_COMM_REG0 + 0x9004)
#define RNPM_FC_PORT_PRIO_MAP(n) (RNPM_COMM_REG0 + 0x9008 + (0x04 * n))
#define RNPM_FC_EN_CONF_AVAILBLE (RNPM_COMM_REG0 + 0x9018)
#define RNPM_FC_UNCTAGS_MAP_OFFSET (16)
/* mac top */
#define RNPM_TOP_MAC_OUI (RNPM_COMM_REG0 + 0xc004)
#define RNPM_TOP_MAC_SN (RNPM_COMM_REG0 + 0xc008)
/* ================================================================== */

/* ==================== RNPM-SERDES Global Registers ================= */

#define RNPM_SERDES (0x40000)

#define RNPM_PCS_OFFSET (0x1000)

#define RNPM_PCS_BASE(i) (RNPM_SERDES + RNPM_PCS_OFFSET * i)
#define RNPM_PCS_1G_OR_10G BIT(13)
#define RNPM_PCS_SPPEED_MASK (0x1c)
#define RNPM_PCS_SPPEED_10G (0x0)
#define RNPM_PCS_SPPEED_40G (0xc)
#define RNPM_PCS_LINK_SPEED (0x30000)
#define RNPM_PCS_LINKUP BIT(2)
#define RNPM_PCS_LINK_STATUS (0x30001)

/* ================================================================== */

/* ==================== RNPM-MAC Global Registers ==================== */
/* === MAC Registers==  */
#define RNPM_XLMAC (0x60000)

#define MAC_OFFSET (0x10000)

#define RNPM_MAC_TX_CFG(i) (RNPM_XLMAC + 0x0000 + i * MAC_OFFSET)

#define RNPM_MAC_RX_CFG(i) (RNPM_XLMAC + 0x0004 + i * MAC_OFFSET)
#define RNPM_RX_ALL BIT(0)
#define RNPM_RX_ALL_MUL BIT(4)
#define RNPM_RX_HUC BIT(1)
#define RNPM_VLAN_HASH_EN BIT(16)
#define RNPM_RA BIT(31)
#define RNPM_HPF BIT(10)
#define RNPM_MAC_PKT_FLT(i) (RNPM_XLMAC + 0x0008 + i * MAC_OFFSET)
#define RNPM_FLT_HMC BIT(2)
#define RNPM_FLT_HUC BIT(1)
#define RNPM_MAC_MC_HASH_TABLE(i, idx)                                         \
	(RNPM_XLMAC + 0x0010 + 0x04 * idx + i * MAC_OFFSET)
#define RNPM_MAC_LPI_CTRL(i) (RNPM_XLMAC + 0x00d0 + i * MAC_OFFSET)

#define RNPM_ERIVLT BIT(27)
#define RNPM_EDVLP BIT(26)
#define RNPM_VTHM BIT(25)
#define RNPM_EVLRXS BIT(24)
#define RNPM_EVLS_OFFSET (21)
#define RNPM_EVLS_ALWAYS_STRIP (0x3)
#define RNPM_DOVLTC BIT(20)
#define RNPM_ERSVLM BIT(19)
#define RNPM_ESVL BIT(18)
#define RNPM_VTIM BIT(17)
#define RNPM_ETV BIT(16)
#define RNPM_VL_MODE_ON (0xFFFF)
#define RNPM_VL_MODE_OFF (0x0000)
#define RNPM_MAC_TX_VLAN_TAG(i) (RNPM_XLMAC + 0x0050 + i * MAC_OFFSET)
#define RNPM_VLTI BIT(20)
#define RNPM_CSVL BIT(19)
#define RNPM_MAC_TX_VLAN_MODE(i) (RNPM_XLMAC + 0x0060 + i * MAC_OFFSET)
#define RNPM_MAC_INNER_VLAN_INCL(i) (RNPM_XLMAC + 0x0064 + i * MAC_OFFSET)
#define RNPM_MAC_VLAN_HASH_TB(i) (RNPM_XLMAC + 0x0058 + i * MAC_OFFSET)

#define RNPM_MAC_Q0_TX_FLOW_CTRL(i, num)                                       \
	(RNPM_XLMAC + 0x0070 + i * MAC_OFFSET + 0x04 * (num))
#define RNPM_MAC_RX_FLOW_CTRL(i) (RNPM_XLMAC + 0x0090 + i * MAC_OFFSET)
#define RNPM_MAC_HW_FEATURE(i) (RNPM_XLMAC + 0x0120 + i * MAC_OFFSET)

#define RNPM_MAC_UNICAST_LOW(i, port)                                          \
	(RNPM_XLMAC + 0x304 + i * 0x08 + port * MAC_OFFSET)
#define RNPM_MAC_UNICAST_HIGH(i, port)                                         \
	(RNPM_XLMAC + 0x300 + i * 0x08 + port * MAC_OFFSET)
/* 1588 */
#define RNPM_MAC_TS_CTRL(i) (RNPM_XLMAC + 0X0d00 + i * MAC_OFFSET)
#define RNPM_MAC_SUB_SECOND_INCREMENT(i) (RNPM_XLMAC + 0x0d04 + i * MAC_OFFSET)
#define RNPM_MAC_SYS_TIME_SEC_CFG(i) (RNPM_XLMAC + 0x0d08 + i * MAC_OFFSET)
#define RNPM_MAC_SYS_TIME_NANOSEC_CFG(i) (RNPM_XLMAC + 0x0d0c + i * MAC_OFFSET)
#define RNPM_MAC_SYS_TIME_SEC_UPDATE(i) (RNPM_XLMAC + 0x0d10 + i * MAC_OFFSET)
#define RNPM_MAC_SYS_TIME_NANOSEC_UPDATE(i)                                    \
	(RNPM_XLMAC + 0x0d14 + i * MAC_OFFSET)
#define RNPM_MAC_TS_ADDEND(i) (RNPM_XLMAC + 0x0d18 + i * MAC_OFFSET)
#define RNPM_MAC_TS_STATS(i) (RNPM_XLMAC + 0x0d20 + i * MAC_OFFSET)
#define RNPM_MAC_INTERRUPT_ENABLE(i) (RNPM_XLMAC + 0x00b4 + i * MAC_OFFSET)

#define RNPM_MAC_STATS_BROADCAST_LOW(i) (RNPM_XLMAC + 0x0918 + i * MAC_OFFSET)
#define RNPM_MAC_STATS_BROADCAST_HIGH(i) (RNPM_XLMAC + 0x091c + i * MAC_OFFSET)
#define RNPM_MAC_STATS_MULTICAST_LOW(i) (RNPM_XLMAC + 0x0920 + i * MAC_OFFSET)
#define RNPM_MAC_STATS_MULTICAST_HIGH(i) (RNPM_XLMAC + 0x0924 + i * MAC_OFFSET)

#define RNPM_MAC_STATS_RX_PAUSE_LOW(i) (RNPM_XLMAC + 0x0988 + i * MAC_OFFSET)
#define RNPM_MAC_STATS_RX_PAUSE_HIGH(i) (RNPM_XLMAC + 0x098c + i * MAC_OFFSET)

#define RNPM_MAC_STATS_TX_PAUSE_LOW(i) (RNPM_XLMAC + 0x0894 + i * MAC_OFFSET)
#define RNPM_MAC_STATS_TX_PAUSE_HIGH(i) (RNPM_XLMAC + 0x0898 + i * MAC_OFFSET)

#define RNPM_TX_FLOW_ENABLE_MASK (0x2)
#define RNPM_RX_FLOW_ENABLE_MASK (0x1)
/* ================================================================== */

/* ==================== RNPM-MSIX Global Registers ==================== */
//==== Ring-MSIX Registers (MSI-X_module_design.docs) ===
#define RING_VECTOR(n) (0x04 * (n))

/* ================================================================== */

/* ==================== RNPM-SWITCH Global Registers ================= */
#define RNPM_SWITCH_BASE (0xB0000)

/* port is 6 */
#define RNPM_SWITCH_RULE_INGS(port, n)                                         \
	(RNPM_SWITCH_BASE + 0x24 * (port) + 0x1000 + 0x04 * (n))
#define RNPM_SWITCH_RULE_INGS_RPU_NP(port)                                     \
	(RNPM_SWITCH_BASE + 0x24 * (port) + 0x1014)
#define RNPM_SWITCH_RULE_INGS_RPU_SWITCH(port)                                 \
	(RNPM_SWITCH_BASE + 0x24 * (port) + 0x1018)
#define RNPM_SWITCH_RULE_INGS_SEC(port)                                        \
	(RNPM_SWITCH_BASE + 0x24 * (port) + 0x101c)
#define RNPM_SWITCH_RULE_INGS_EXFPGA(port)                                     \
	(RNPM_SWITCH_BASE + 0x24 * (port) + 0x1020)
#define RNPM_SWITCH_CNT_EGRESS_PKT(port)                                       \
	(RNPM_SWITCH_BASE + 0x10db + 0x04 * (n))
#define RNPM_SWITCH_CNT_INGRESS_PKT(port)                                      \
	(RNPM_SWITCH_BASE + 0x10f0 + 0x04 * (n))
#define RNPM_SWITCH_RPUUP_DATA_PROG_FULL_THRESH (RNPM_SWITCH_BASE + 0x1108)
#define RNPM_SWITCH_RPUDN_DATA_PROG_FULL_THRESH (RNPM_SWITCH_BASE + 0x110c)
#define RNPM_SWITCH_MAC0_DATA_PROG_FULL_THRESH (RNPM_SWITCH_BASE + 0x1110)
#define RNPM_SWITCH_MAC1_DATA_PROG_FULL_THRESH (RNPM_SWITCH_BASE + 0x1114)
#define RNPM_SWITCH_DMA0_DATA_PROG_FULL_THRESH (RNPM_SWITCH_BASE + 0x1118)
#define RNPM_SWITCH_DMA1_DATA_PROG_FULL_THRESH (RNPM_SWITCH_BASE + 0x111c)
#define RNPM_SWITCH_REG1_INGRESS_STATUS(port)                                  \
	(RNPM_SWITCH_BASE + 0x1120 + 0x08 * (port))
#define RNPM_SWITCH_REG2_INGRESS_STATUS(port)                                  \
	(RNPM_SWITCH_BASE + 0x1124 + 0x08 * (port))
#define RNPM_SWITCH_REG_STATUS_ROBIN(port)                                     \
	(RNPM_SWITCH_BASE + 0x1150 + 0x04 * (port))
#define RNPM_SWITCH_REG_EGRESS_STATUS(port)                                    \
	(RNPM_SWITCH_BASE + 0x1168 + 0x04 * (port))
#define RNPM_SWITCH_INFO_FIFO_DMA_TX(n) (RNPM_SWITCH_BASE + 0x1198 + 0x08 * (n))
#define RNPM_SWITCH_INFO_FIFO_DMA_RX(n) (RNPM_SWITCH_BASE + 0x119c + 0x08 * (n))
#define RNPM_SWITCH_INFO_FIFO_MAC_TX(n) (RNPM_SWITCH_BASE + 0x11a8 + 0x08 * (n))
#define RNPM_SWITCH_INFO_FIFO_MAC_RX(n) (RNPM_SWITCH_BASE + 0x11ac + 0x08 * (n))
#define RNPM_SWITCH_INFO_FIFO_RPUUP_RX(n)                                      \
	(RNPM_SWITCH_BASE + 0x11bc + 0x08 * (n))
#define RNPM_SWITCH_INFO_FIFO_RPUDN_RX(n)                                      \
	(RNPM_SWITCH_BASE + 0x11c0 + 0x08 * (n))
#define RNPM_SWITCH_EN_SOFT_RESET (RNPM_SWITCH_BASE + 0xf000)
#define RNPM_SWITCH_SOFT_RESET (RNPM_SWITCH_BASE + 0xf004)
#define RNPM_SWITCH_CLR_INGS_ERR (RNPM_SWITCH_BASE + 0xf008)
#define RNPM_SWITCH_ERR_CODE_INGS(port)                                        \
	(RNPM_SWITCH_BASE + 0xf010 + 0x04 * (port))
#define RNPM_SWITCH_MEM_SD (RNPM_SWITCH_BASE + 0xf028)
#define RNPM_SWITCH_MEM_SLP (RNPM_SWITCH_BASE + 0xf02c)
#define RNPM_SWITCH_EN_INVALID_DPORT_DROP_O (RNPM_SWITCH_BASE + 0xf030)

/* ================================================================== */

/* ==================== RNPM-TCAM Global Registers ==================== */
#define RNPM_TCAM_BASE (0xc0000)

#define RNPM_TCAM_SDPQF(n)                                                     \
	(RNPM_TCAM_BASE + 0x00 + 0x40 * (n / 2) + 0x10 * (n % 2))
#define RNPM_TCAM_DAQF(n)                                                      \
	(RNPM_TCAM_BASE + 0x04 + 0x40 * (n / 2) + 0x10 * (n % 2))
#define RNPM_TCAM_SAQF(n)                                                      \
	(RNPM_TCAM_BASE + 0x08 + 0x40 * (n / 2) + 0x10 * (n % 2))
#define RNPM_TCAM_APQF(n)                                                      \
	(RNPM_TCAM_BASE + 0x0c + 0x40 * (n / 2) + 0x10 * (n % 2))
#define RNPM_TCAM_SDPQF_MASK(n)                                                \
	(RNPM_TCAM_BASE + 0x20 + 0x40 * (n / 2) + 0x10 * (n % 2))
#define RNPM_TCAM_DAQF_MASK(n)                                                 \
	(RNPM_TCAM_BASE + 0x24 + 0x40 * (n / 2) + 0x10 * (n % 2))
#define RNPM_TCAM_SAQF_MASK(n)                                                 \
	(RNPM_TCAM_BASE + 0x28 + 0x40 * (n / 2) + 0x10 * (n % 2))
#define RNPM_TCAM_APQF_MASK(n)                                                 \
	(RNPM_TCAM_BASE + 0x2c + 0x40 * (n / 2) + 0x10 * (n % 2))

#define RNPM_TCAM_MODE (RNPM_TCAM_BASE + 0x20000)
#define RNPM_TCAM_CACHE_ENABLE (RNPM_TCAM_BASE + 0x20004)
#define RNPM_TCAM_CACHE_ADDR_CLR (RNPM_TCAM_BASE + 0x20008)
#define RNPM_TCAM_CACHE_REQ_CLR (RNPM_TCAM_BASE + 0x2000c)

/* ================================================================== */

/* ==================== OTHER Global Registers ==================== */
/* =====  PF-VF Functions ==== */
#define VF_NUM_REG (0xa3000)
/* 8bit: 7:vf_actiove 6:fun0/fun1 [5:0]:vf_num */
#define VF_NUM(vfnum, fun) ((1 << 7) | (((fun) & 0x1) << 6) | ((vfnum) & 0x3F))
#define PF_NUM(fun) (((fun) & 0x1) << 6)

#define IS_VF(vfnum) (((vfnum) & (1 << 7)) ? 1 : 0)

/* PFC Flow Control*/
enum NIC_MODE {
	MODE_NIC_MODE_1PORT_40G = 0,
	MODE_NIC_MODE_1PORT = 1,
	MODE_NIC_MODE_2PORT = 2,
	MODE_NIC_MODE_4PORT = 3,
};

/* ================================================================== */
#endif /* RNPM_REGS_H */
