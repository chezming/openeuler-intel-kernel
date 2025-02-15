{
	"raw_stack: no skb_load_bytes",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 4),
	BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -8),
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
	BPF_MOV64_IMM(BPF_REG_4, 8),
	/* Call to skb_load_bytes() omitted. */
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.retval = POINTER_VALUE,
	.errstr_unpriv = "invalid read from stack R6 off=-8 size=8",
	.result_unpriv = REJECT,
},
{
	"raw_stack: skb_load_bytes, negative len",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 4),
	BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -8),
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
	BPF_MOV64_IMM(BPF_REG_4, -8),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "R4 min value is negative",
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
},
{
	"raw_stack: skb_load_bytes, negative len 2",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 4),
	BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -8),
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
	BPF_MOV64_IMM(BPF_REG_4, ~0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "R4 min value is negative",
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
},
{
	"raw_stack: skb_load_bytes, zero len",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 4),
	BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -8),
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "invalid zero-sized read",
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
},
{
	"raw_stack: skb_load_bytes, no init",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 4),
	BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -8),
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
	BPF_MOV64_IMM(BPF_REG_4, 8),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
},
{
	"raw_stack: skb_load_bytes, init",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 4),
	BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -8),
	BPF_ST_MEM(BPF_DW, BPF_REG_6, 0, 0xcafe),
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
	BPF_MOV64_IMM(BPF_REG_4, 8),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
},
{
	"raw_stack: skb_load_bytes, spilled regs around bounds",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 4),
	BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -16),
	BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, -8),
	BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1,  8),
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
	BPF_MOV64_IMM(BPF_REG_4, 8),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, -8),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6,  8),
	BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_0,
		    offsetof(struct __sk_buff, mark)),
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_2,
		    offsetof(struct __sk_buff, priority)),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_2),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
},
{
	"raw_stack: skb_load_bytes, spilled regs corruption",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 4),
	BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -8),
	BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, 0),
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
	BPF_MOV64_IMM(BPF_REG_4, 8),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
	BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_0,
		    offsetof(struct __sk_buff, mark)),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "R0 invalid mem access 'inv'",
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"raw_stack: skb_load_bytes, spilled regs corruption 2",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 4),
	BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -16),
	BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, -8),
	BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1,  0),
	BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1,  8),
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
	BPF_MOV64_IMM(BPF_REG_4, 8),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, -8),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6,  8),
	BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_6,  0),
	BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_0,
		    offsetof(struct __sk_buff, mark)),
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_2,
		    offsetof(struct __sk_buff, priority)),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_2),
	BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_3,
		    offsetof(struct __sk_buff, pkt_type)),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_3),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "R3 invalid mem access 'inv'",
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.flags = F_NEEDS_EFFICIENT_UNALIGNED_ACCESS,
},
{
	"raw_stack: skb_load_bytes, spilled regs + data",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 4),
	BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -16),
	BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, -8),
	BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1,  0),
	BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1,  8),
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
	BPF_MOV64_IMM(BPF_REG_4, 8),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, -8),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6,  8),
	BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_6,  0),
	BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_0,
		    offsetof(struct __sk_buff, mark)),
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_2,
		    offsetof(struct __sk_buff, priority)),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_2),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_3),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
},
{
	"raw_stack: skb_load_bytes, invalid access 1",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 4),
	BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -513),
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
	BPF_MOV64_IMM(BPF_REG_4, 8),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "invalid indirect access to stack R3 off=-513 size=8",
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
},
{
	"raw_stack: skb_load_bytes, invalid access 2",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 4),
	BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -1),
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
	BPF_MOV64_IMM(BPF_REG_4, 8),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "invalid indirect access to stack R3 off=-1 size=8",
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
},
{
	"raw_stack: skb_load_bytes, invalid access 3",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 4),
	BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 0xffffffff),
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
	BPF_MOV64_IMM(BPF_REG_4, 0xffffffff),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "R4 min value is negative",
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
},
{
	"raw_stack: skb_load_bytes, invalid access 4",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 4),
	BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -1),
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
	BPF_MOV64_IMM(BPF_REG_4, 0x7fffffff),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "R4 unbounded memory access, use 'var &= const' or 'if (var < const)'",
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
},
{
	"raw_stack: skb_load_bytes, invalid access 5",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 4),
	BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -512),
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
	BPF_MOV64_IMM(BPF_REG_4, 0x7fffffff),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "R4 unbounded memory access, use 'var &= const' or 'if (var < const)'",
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
},
{
	"raw_stack: skb_load_bytes, invalid access 6",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 4),
	BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -512),
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
	BPF_MOV64_IMM(BPF_REG_4, 0),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "invalid zero-sized read",
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
},
{
	"raw_stack: skb_load_bytes, large access",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_2, 4),
	BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -512),
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
	BPF_MOV64_IMM(BPF_REG_4, 512),
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
},
