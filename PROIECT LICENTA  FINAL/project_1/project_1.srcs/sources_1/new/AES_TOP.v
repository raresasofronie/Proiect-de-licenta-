`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 03/18/2025 
// Design Name: 
// Module Name: AES_TB
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module AES_TOP(
    input wire clk,
    input wire rst,
    input wire rx,
    output wire tx
);

    parameter CLKS_PER_BIT = 10416; 

    // UART RX
    wire rx_dv;
    wire [7:0] rx_byte;
    uart_rx #(.CLKS_PER_BIT(CLKS_PER_BIT)) uart_rx_inst (
        .i_Clock(clk),
        .i_Rx_Serial(rx),
        .o_Rx_DV(rx_dv),
        .o_Rx_Byte(rx_byte)
    );

    // UART TX
    reg tx_dv = 0;
    reg [7:0] tx_byte = 0;
    wire tx_active;
    wire tx_serial;
    uart_tx #(.CLKS_PER_BIT(CLKS_PER_BIT)) uart_tx_inst (
        .i_Clock(clk),
        .i_Tx_DV(tx_dv),
        .i_Tx_Byte(tx_byte),
        .o_Tx_Active(tx_active),
        .o_Tx_Serial(tx_serial),
        .o_Tx_Done()
    );
    assign tx = tx_serial;

    reg mode_reg = 0; 
    reg [127:0] key_buf = 0;
    reg [127:0] data_buf = 0;
    reg [5:0] byte_cnt = 0;
    

    reg sending = 0;
    
    // Pentru criptare: 0: input, 1:k_sch, 2:start, 3:s_row, 4:m_col, 5:k_sch, 6:output
    // Pentru decriptare: 0:iinput, 1:ik_sch, 2:istart, 3:is_row, 4:is_box, 5:ik_sch, 6:ik_add, 7:imix
    reg [2:0] step = 0; 
    reg [3:0] send_cnt = 0;
    reg [3:0] round_num = 0;
    reg [127:0] last_addroundkey = 0;

    wire [127:0] r0_addroundkey_out;
    wire [1407:0] round_keys_out;
    wire key_exp_done;



    reg key_exp_start = 0;
    aes_key_expansion key_expansion_unit (
        .clk(clk),
        .rst(rst),
        .start(key_exp_start),
        .key_in(key_buf),
        .round_keys_out(round_keys_out),
        .done(key_exp_done)
    );


    aes_encryption_finale xor_stage (
        .initial_msg(data_buf),
        .key(key_buf),
        .xor_msg(r0_addroundkey_out)
    );

    wire [127:0] r1_subbytes_wire;
    wire [127:0] r1_shiftrows_wire;
    wire [127:0] r1_mixcolumns_wire;
    wire [127:0] r1_addroundkey_wire;
    aes_sub_bytes r1_subbytes(.state_in(r0_addroundkey_out), .state_out(r1_subbytes_wire));
    aes_shift_rows r1_shiftrows(.state_in(r1_subbytes_wire), .state_out(r1_shiftrows_wire));
    aes_mix_columns r1_mixcolumns(.state_in(r1_shiftrows_wire), .state_out(r1_mixcolumns_wire));
    aes_add_round_key r1_addroundkey(
        .state_in(r1_mixcolumns_wire),
        .round_key(round_keys_out[1279 -: 128]),
        .state_out(r1_addroundkey_wire)
    );



    wire [127:0] r2_subbytes_wire;
    wire [127:0] r2_shiftrows_wire;
    wire [127:0] r2_mixcolumns_wire;
    wire [127:0] r2_addroundkey_wire;
    aes_sub_bytes r2_subbytes(.state_in(r1_addroundkey_wire), .state_out(r2_subbytes_wire));
    aes_shift_rows r2_shiftrows(.state_in(r2_subbytes_wire), .state_out(r2_shiftrows_wire));
    aes_mix_columns r2_mixcolumns(.state_in(r2_shiftrows_wire), .state_out(r2_mixcolumns_wire));
    aes_add_round_key r2_addroundkey(
        .state_in(r2_mixcolumns_wire),
        .round_key(round_keys_out[1151 -: 128]),
        .state_out(r2_addroundkey_wire)
    );



    wire [127:0] r3_subbytes_wire;
    wire [127:0] r3_shiftrows_wire;
    wire [127:0] r3_mixcolumns_wire;
    wire [127:0] r3_addroundkey_wire;
    aes_sub_bytes r3_subbytes(.state_in(r2_addroundkey_wire), .state_out(r3_subbytes_wire));
    aes_shift_rows r3_shiftrows(.state_in(r3_subbytes_wire), .state_out(r3_shiftrows_wire));
    aes_mix_columns r3_mixcolumns(.state_in(r3_shiftrows_wire), .state_out(r3_mixcolumns_wire));
    aes_add_round_key r3_addroundkey(
        .state_in(r3_mixcolumns_wire),
        .round_key(round_keys_out[1023 -: 128]),
        .state_out(r3_addroundkey_wire)
    );



    wire [127:0] r4_subbytes_wire;
    wire [127:0] r4_shiftrows_wire;
    wire [127:0] r4_mixcolumns_wire;
    wire [127:0] r4_addroundkey_wire;
    aes_sub_bytes r4_subbytes(.state_in(r3_addroundkey_wire), .state_out(r4_subbytes_wire));
    aes_shift_rows r4_shiftrows(.state_in(r4_subbytes_wire), .state_out(r4_shiftrows_wire));
    aes_mix_columns r4_mixcolumns(.state_in(r4_shiftrows_wire), .state_out(r4_mixcolumns_wire));
    aes_add_round_key r4_addroundkey(
        .state_in(r4_mixcolumns_wire),
        .round_key(round_keys_out[895 -: 128]),
        .state_out(r4_addroundkey_wire)
    );




    wire [127:0] r5_subbytes_wire;
    wire [127:0] r5_shiftrows_wire;
    wire [127:0] r5_mixcolumns_wire;
    wire [127:0] r5_addroundkey_wire;
    aes_sub_bytes r5_subbytes(.state_in(r4_addroundkey_wire), .state_out(r5_subbytes_wire));
    aes_shift_rows r5_shiftrows(.state_in(r5_subbytes_wire), .state_out(r5_shiftrows_wire));
    aes_mix_columns r5_mixcolumns(.state_in(r5_shiftrows_wire), .state_out(r5_mixcolumns_wire));
    aes_add_round_key r5_addroundkey(
        .state_in(r5_mixcolumns_wire),
        .round_key(round_keys_out[767 -: 128]),
        .state_out(r5_addroundkey_wire)
    );




    wire [127:0] r6_subbytes_wire;
    wire [127:0] r6_shiftrows_wire;
    wire [127:0] r6_mixcolumns_wire;
    wire [127:0] r6_addroundkey_wire;
    aes_sub_bytes r6_subbytes(.state_in(r5_addroundkey_wire), .state_out(r6_subbytes_wire));
    aes_shift_rows r6_shiftrows(.state_in(r6_subbytes_wire), .state_out(r6_shiftrows_wire));
    aes_mix_columns r6_mixcolumns(.state_in(r6_shiftrows_wire), .state_out(r6_mixcolumns_wire));
    aes_add_round_key r6_addroundkey(
        .state_in(r6_mixcolumns_wire),
        .round_key(round_keys_out[639 -: 128]),
        .state_out(r6_addroundkey_wire)
    );



    wire [127:0] r7_subbytes_wire;
    wire [127:0] r7_shiftrows_wire;
    wire [127:0] r7_mixcolumns_wire;
    wire [127:0] r7_addroundkey_wire;
    aes_sub_bytes r7_subbytes(.state_in(r6_addroundkey_wire), .state_out(r7_subbytes_wire));
    aes_shift_rows r7_shiftrows(.state_in(r7_subbytes_wire), .state_out(r7_shiftrows_wire));
    aes_mix_columns r7_mixcolumns(.state_in(r7_shiftrows_wire), .state_out(r7_mixcolumns_wire));
    aes_add_round_key r7_addroundkey(
        .state_in(r7_mixcolumns_wire),
        .round_key(round_keys_out[511 -: 128]),
        .state_out(r7_addroundkey_wire)
    );



    wire [127:0] r8_subbytes_wire;
    wire [127:0] r8_shiftrows_wire;
    wire [127:0] r8_mixcolumns_wire;
    wire [127:0] r8_addroundkey_wire;
    aes_sub_bytes r8_subbytes(.state_in(r7_addroundkey_wire), .state_out(r8_subbytes_wire));
    aes_shift_rows r8_shiftrows(.state_in(r8_subbytes_wire), .state_out(r8_shiftrows_wire));
    aes_mix_columns r8_mixcolumns(.state_in(r8_shiftrows_wire), .state_out(r8_mixcolumns_wire));
    aes_add_round_key r8_addroundkey(
        .state_in(r8_mixcolumns_wire),
        .round_key(round_keys_out[383 -: 128]),
        .state_out(r8_addroundkey_wire)
    );




    wire [127:0] r9_subbytes_wire;
    wire [127:0] r9_shiftrows_wire;
    wire [127:0] r9_mixcolumns_wire;
    wire [127:0] r9_addroundkey_wire;
    aes_sub_bytes r9_subbytes(.state_in(r8_addroundkey_wire), .state_out(r9_subbytes_wire));
    aes_shift_rows r9_shiftrows(.state_in(r9_subbytes_wire), .state_out(r9_shiftrows_wire));
    aes_mix_columns r9_mixcolumns(.state_in(r9_shiftrows_wire), .state_out(r9_mixcolumns_wire));
    aes_add_round_key r9_addroundkey(
        .state_in(r9_mixcolumns_wire),
        .round_key(round_keys_out[255 -: 128]),
        .state_out(r9_addroundkey_wire)
    );



    wire [127:0] r10_subbytes_wire;
    wire [127:0] r10_shiftrows_wire;
    wire [127:0] r10_addroundkey_wire;
    aes_sub_bytes r10_subbytes(.state_in(r9_addroundkey_wire), .state_out(r10_subbytes_wire));
    aes_shift_rows r10_shiftrows(.state_in(r10_subbytes_wire), .state_out(r10_shiftrows_wire));
    aes_add_round_key r10_addroundkey(
        .state_in(r10_shiftrows_wire),
        .round_key(round_keys_out[127 -: 128]),
        .state_out(r10_addroundkey_wire)
    );



    reg [127:0] r1_subbytes_reg, r1_shiftrows_reg, r1_mixcolumns_reg, r1_addroundkey_reg;
    reg [127:0] r2_subbytes_reg, r2_shiftrows_reg, r2_mixcolumns_reg, r2_addroundkey_reg;
    reg [127:0] r3_subbytes_reg, r3_shiftrows_reg, r3_mixcolumns_reg, r3_addroundkey_reg;
    reg [127:0] r4_subbytes_reg, r4_shiftrows_reg, r4_mixcolumns_reg, r4_addroundkey_reg;
    reg [127:0] r5_subbytes_reg, r5_shiftrows_reg, r5_mixcolumns_reg, r5_addroundkey_reg;
    reg [127:0] r6_subbytes_reg, r6_shiftrows_reg, r6_mixcolumns_reg, r6_addroundkey_reg;
    reg [127:0] r7_subbytes_reg, r7_shiftrows_reg, r7_mixcolumns_reg, r7_addroundkey_reg;
    reg [127:0] r8_subbytes_reg, r8_shiftrows_reg, r8_mixcolumns_reg, r8_addroundkey_reg;
    reg [127:0] r9_subbytes_reg, r9_shiftrows_reg, r9_mixcolumns_reg, r9_addroundkey_reg;
    reg [127:0] r10_subbytes_reg, r10_shiftrows_reg, r10_addroundkey_reg;




    wire [127:0] r0_invaddroundkey_out;
    aes_add_round_key r0_invaddroundkey (
        .state_in(data_buf),
        .round_key(round_keys_out[127 -: 128]), 
        .state_out(r0_invaddroundkey_out)
    );



    wire [127:0] r1_invshiftrows_out;
    wire [127:0] r1_invsubbytes_out;
    wire [127:0] r1_invaddroundkey_out;
    wire [127:0] r1_invmixcolumns_out;
    aes_shift_rows_inv r1_invshiftrows (
        .state_in(r0_invaddroundkey_out),
        .state_out(r1_invshiftrows_out)
    );
    
    aes_sub_bytes_inv r1_invsubbytes (
        .state_in(r1_invshiftrows_out),
        .state_out(r1_invsubbytes_out)
    );
    
    aes_add_round_key r1_invaddroundkey (
        .state_in(r1_invsubbytes_out),
        .round_key(round_keys_out[255 -: 128]), 
        .state_out(r1_invaddroundkey_out)
    );
    
    aes_mix_columns_inv r1_invmixcolumns (
        .state_in(r1_invaddroundkey_out),
        .state_out(r1_invmixcolumns_out)
    );



    wire [127:0] r2_invshiftrows_out;
    wire [127:0] r2_invsubbytes_out;
    wire [127:0] r2_invaddroundkey_out;
    wire [127:0] r2_invmixcolumns_out;
    
    aes_shift_rows_inv r2_invshiftrows (
        .state_in(r1_invmixcolumns_out),
        .state_out(r2_invshiftrows_out)
    );
    
    aes_sub_bytes_inv r2_invsubbytes (
        .state_in(r2_invshiftrows_out),
        .state_out(r2_invsubbytes_out)
    );
    
    aes_add_round_key r2_invaddroundkey (
        .state_in(r2_invsubbytes_out),
        .round_key(round_keys_out[383 -: 128]), 
        .state_out(r2_invaddroundkey_out)
    );
    
    aes_mix_columns_inv r2_invmixcolumns (
        .state_in(r2_invaddroundkey_out),
        .state_out(r2_invmixcolumns_out)
    );



    wire [127:0] r3_invshiftrows_out;
    wire [127:0] r3_invsubbytes_out;
    wire [127:0] r3_invaddroundkey_out;
    wire [127:0] r3_invmixcolumns_out;
    
    aes_shift_rows_inv r3_invshiftrows (
        .state_in(r2_invmixcolumns_out),
        .state_out(r3_invshiftrows_out)
    );
    
    aes_sub_bytes_inv r3_invsubbytes (
        .state_in(r3_invshiftrows_out),
        .state_out(r3_invsubbytes_out)
    );
    
    aes_add_round_key r3_invaddroundkey (
        .state_in(r3_invsubbytes_out),
        .round_key(round_keys_out[511 -: 128]), 
        .state_out(r3_invaddroundkey_out)
    );
    
    aes_mix_columns_inv r3_invmixcolumns (
        .state_in(r3_invaddroundkey_out),
        .state_out(r3_invmixcolumns_out)
    );




    wire [127:0] r4_invshiftrows_out;
    wire [127:0] r4_invsubbytes_out;
    wire [127:0] r4_invaddroundkey_out;
    wire [127:0] r4_invmixcolumns_out;
    
    aes_shift_rows_inv r4_invshiftrows (
        .state_in(r3_invmixcolumns_out),
        .state_out(r4_invshiftrows_out)
    );
    
    aes_sub_bytes_inv r4_invsubbytes (
        .state_in(r4_invshiftrows_out),
        .state_out(r4_invsubbytes_out)
    );
    
    aes_add_round_key r4_invaddroundkey (
        .state_in(r4_invsubbytes_out),
        .round_key(round_keys_out[639 -: 128]), 
        .state_out(r4_invaddroundkey_out)
    );
    
    aes_mix_columns_inv r4_invmixcolumns (
        .state_in(r4_invaddroundkey_out),
        .state_out(r4_invmixcolumns_out)
    );



    wire [127:0] r5_invshiftrows_out;
    wire [127:0] r5_invsubbytes_out;
    wire [127:0] r5_invaddroundkey_out;
    wire [127:0] r5_invmixcolumns_out;
    
    aes_shift_rows_inv r5_invshiftrows (
        .state_in(r4_invmixcolumns_out),
        .state_out(r5_invshiftrows_out)
    );
    
    aes_sub_bytes_inv r5_invsubbytes (
        .state_in(r5_invshiftrows_out),
        .state_out(r5_invsubbytes_out)
    );
    
    aes_add_round_key r5_invaddroundkey (
        .state_in(r5_invsubbytes_out),
        .round_key(round_keys_out[767 -: 128]), 
        .state_out(r5_invaddroundkey_out)
    );
    
    aes_mix_columns_inv r5_invmixcolumns (
        .state_in(r5_invaddroundkey_out),
        .state_out(r5_invmixcolumns_out)
    );


    wire [127:0] r6_invshiftrows_out;
    wire [127:0] r6_invsubbytes_out;
    wire [127:0] r6_invaddroundkey_out;
    wire [127:0] r6_invmixcolumns_out;
    
    aes_shift_rows_inv r6_invshiftrows (
        .state_in(r5_invmixcolumns_out),
        .state_out(r6_invshiftrows_out)
    );
    
    aes_sub_bytes_inv r6_invsubbytes (
        .state_in(r6_invshiftrows_out),
        .state_out(r6_invsubbytes_out)
    );
    
    aes_add_round_key r6_invaddroundkey (
        .state_in(r6_invsubbytes_out),
        .round_key(round_keys_out[895 -: 128]), 
        .state_out(r6_invaddroundkey_out)
    );
    
    aes_mix_columns_inv r6_invmixcolumns (
        .state_in(r6_invaddroundkey_out),
        .state_out(r6_invmixcolumns_out)
    );




    wire [127:0] r7_invshiftrows_out;
    wire [127:0] r7_invsubbytes_out;
    wire [127:0] r7_invaddroundkey_out;
    wire [127:0] r7_invmixcolumns_out;
    
    aes_shift_rows_inv r7_invshiftrows (
        .state_in(r6_invmixcolumns_out),
        .state_out(r7_invshiftrows_out)
    );
    
    aes_sub_bytes_inv r7_invsubbytes (
        .state_in(r7_invshiftrows_out),
        .state_out(r7_invsubbytes_out)
    );
    
    aes_add_round_key r7_invaddroundkey (
        .state_in(r7_invsubbytes_out),
        .round_key(round_keys_out[1023 -: 128]), 
        .state_out(r7_invaddroundkey_out)
    );
    
    aes_mix_columns_inv r7_invmixcolumns (
        .state_in(r7_invaddroundkey_out),
        .state_out(r7_invmixcolumns_out)
    );


    wire [127:0] r8_invshiftrows_out;
    wire [127:0] r8_invsubbytes_out;
    wire [127:0] r8_invaddroundkey_out;
    wire [127:0] r8_invmixcolumns_out;
    
    aes_shift_rows_inv r8_invshiftrows (
        .state_in(r7_invmixcolumns_out),
        .state_out(r8_invshiftrows_out)
    );
    
    aes_sub_bytes_inv r8_invsubbytes (
        .state_in(r8_invshiftrows_out),
        .state_out(r8_invsubbytes_out)
    );
    
    aes_add_round_key r8_invaddroundkey (
        .state_in(r8_invsubbytes_out),
        .round_key(round_keys_out[1151 -: 128]), 
        .state_out(r8_invaddroundkey_out)
    );
    
    aes_mix_columns_inv r8_invmixcolumns (
        .state_in(r8_invaddroundkey_out),
        .state_out(r8_invmixcolumns_out)
    );



    wire [127:0] r9_invshiftrows_out;
    wire [127:0] r9_invsubbytes_out;
    wire [127:0] r9_invaddroundkey_out;
    wire [127:0] r9_invmixcolumns_out;
    
    aes_shift_rows_inv r9_invshiftrows (
        .state_in(r8_invmixcolumns_out),
        .state_out(r9_invshiftrows_out)
    );
    
    aes_sub_bytes_inv r9_invsubbytes (
        .state_in(r9_invshiftrows_out),
        .state_out(r9_invsubbytes_out)
    );
    
    aes_add_round_key r9_invaddroundkey (
        .state_in(r9_invsubbytes_out),
        .round_key(round_keys_out[1279 -: 128]), 
        .state_out(r9_invaddroundkey_out)
    );
    
    aes_mix_columns_inv r9_invmixcolumns (
        .state_in(r9_invaddroundkey_out),
        .state_out(r9_invmixcolumns_out)
    );

    wire [127:0] r10_invshiftrows_out;
    wire [127:0] r10_invsubbytes_out;
    wire [127:0] r10_invaddroundkey_out;
    
    aes_shift_rows_inv r10_invshiftrows (
        .state_in(r9_invmixcolumns_out),
        .state_out(r10_invshiftrows_out)
    );
    
    aes_sub_bytes_inv r10_invsubbytes (
        .state_in(r10_invshiftrows_out),
        .state_out(r10_invsubbytes_out)
    );
    
    aes_add_round_key r10_invaddroundkey (
        .state_in(r10_invsubbytes_out),
        .round_key(round_keys_out[1407 -: 128]), 
        .state_out(r10_invaddroundkey_out)
    );


    reg [127:0] r0_invaddroundkey_reg;
    reg [127:0] r1_invshiftrows_reg, r1_invsubbytes_reg, r1_invaddroundkey_reg, r1_invmixcolumns_reg;
    reg [127:0] r2_invshiftrows_reg, r2_invsubbytes_reg, r2_invaddroundkey_reg, r2_invmixcolumns_reg;
    reg [127:0] r3_invshiftrows_reg, r3_invsubbytes_reg, r3_invaddroundkey_reg, r3_invmixcolumns_reg;
    reg [127:0] r4_invshiftrows_reg, r4_invsubbytes_reg, r4_invaddroundkey_reg, r4_invmixcolumns_reg;
    reg [127:0] r5_invshiftrows_reg, r5_invsubbytes_reg, r5_invaddroundkey_reg, r5_invmixcolumns_reg;
    reg [127:0] r6_invshiftrows_reg, r6_invsubbytes_reg, r6_invaddroundkey_reg, r6_invmixcolumns_reg;
    reg [127:0] r7_invshiftrows_reg, r7_invsubbytes_reg, r7_invaddroundkey_reg, r7_invmixcolumns_reg;
    reg [127:0] r8_invshiftrows_reg, r8_invsubbytes_reg, r8_invaddroundkey_reg, r8_invmixcolumns_reg;
    reg [127:0] r9_invshiftrows_reg, r9_invsubbytes_reg, r9_invaddroundkey_reg, r9_invmixcolumns_reg;
    reg [127:0] r10_invshiftrows_reg, r10_invsubbytes_reg, r10_invaddroundkey_reg;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            mode_reg <= 0;
            r1_subbytes_reg <= 0; r1_shiftrows_reg <= 0; r1_mixcolumns_reg <= 0; r1_addroundkey_reg <= 0;
            r2_subbytes_reg <= 0; r2_shiftrows_reg <= 0; r2_mixcolumns_reg <= 0; r2_addroundkey_reg <= 0;
            r3_subbytes_reg <= 0; r3_shiftrows_reg <= 0; r3_mixcolumns_reg <= 0; r3_addroundkey_reg <= 0;
            r4_subbytes_reg <= 0; r4_shiftrows_reg <= 0; r4_mixcolumns_reg <= 0; r4_addroundkey_reg <= 0;
            r5_subbytes_reg <= 0; r5_shiftrows_reg <= 0; r5_mixcolumns_reg <= 0; r5_addroundkey_reg <= 0;
            r6_subbytes_reg <= 0; r6_shiftrows_reg <= 0; r6_mixcolumns_reg <= 0; r6_addroundkey_reg <= 0;
            r7_subbytes_reg <= 0; r7_shiftrows_reg <= 0; r7_mixcolumns_reg <= 0; r7_addroundkey_reg <= 0;
            r8_subbytes_reg <= 0; r8_shiftrows_reg <= 0; r8_mixcolumns_reg <= 0; r8_addroundkey_reg <= 0;
            r9_subbytes_reg <= 0; r9_shiftrows_reg <= 0; r9_mixcolumns_reg <= 0; r9_addroundkey_reg <= 0;
            r10_subbytes_reg <= 0; r10_shiftrows_reg <= 0; r10_addroundkey_reg <= 0;



            r0_invaddroundkey_reg <= 0;
            r1_invshiftrows_reg <= 0; r1_invsubbytes_reg <= 0; r1_invaddroundkey_reg <= 0; r1_invmixcolumns_reg <= 0;
            r2_invshiftrows_reg <= 0; r2_invsubbytes_reg <= 0; r2_invaddroundkey_reg <= 0; r2_invmixcolumns_reg <= 0;
            r3_invshiftrows_reg <= 0; r3_invsubbytes_reg <= 0; r3_invaddroundkey_reg <= 0; r3_invmixcolumns_reg <= 0;
            r4_invshiftrows_reg <= 0; r4_invsubbytes_reg <= 0; r4_invaddroundkey_reg <= 0; r4_invmixcolumns_reg <= 0;
            r5_invshiftrows_reg <= 0; r5_invsubbytes_reg <= 0; r5_invaddroundkey_reg <= 0; r5_invmixcolumns_reg <= 0;
            r6_invshiftrows_reg <= 0; r6_invsubbytes_reg <= 0; r6_invaddroundkey_reg <= 0; r6_invmixcolumns_reg <= 0;
            r7_invshiftrows_reg <= 0; r7_invsubbytes_reg <= 0; r7_invaddroundkey_reg <= 0; r7_invmixcolumns_reg <= 0;
            r8_invshiftrows_reg <= 0; r8_invsubbytes_reg <= 0; r8_invaddroundkey_reg <= 0; r8_invmixcolumns_reg <= 0;
            r9_invshiftrows_reg <= 0; r9_invsubbytes_reg <= 0; r9_invaddroundkey_reg <= 0; r9_invmixcolumns_reg <= 0;
            r10_invshiftrows_reg <= 0; r10_invsubbytes_reg <= 0; r10_invaddroundkey_reg <= 0;

            byte_cnt <= 0;
            key_buf <= 0;
            data_buf <= 0;
            sending <= 0;
            step <= 0;
            send_cnt <= 0;
            round_num <= 0;
            tx_dv <= 0;
            tx_byte <= 0;
            key_exp_start <= 0;
            last_addroundkey <= 0;
        end else begin
            r1_subbytes_reg <= r1_subbytes_wire;
            r1_shiftrows_reg <= r1_shiftrows_wire;
            r1_mixcolumns_reg <= r1_mixcolumns_wire;
            r1_addroundkey_reg <= r1_addroundkey_wire;

            r2_subbytes_reg <= r2_subbytes_wire;
            r2_shiftrows_reg <= r2_shiftrows_wire;
            r2_mixcolumns_reg <= r2_mixcolumns_wire;
            r2_addroundkey_reg <= r2_addroundkey_wire;

            r3_subbytes_reg <= r3_subbytes_wire;
            r3_shiftrows_reg <= r3_shiftrows_wire;
            r3_mixcolumns_reg <= r3_mixcolumns_wire;
            r3_addroundkey_reg <= r3_addroundkey_wire;

            r4_subbytes_reg <= r4_subbytes_wire;
            r4_shiftrows_reg <= r4_shiftrows_wire;
            r4_mixcolumns_reg <= r4_mixcolumns_wire;
            r4_addroundkey_reg <= r4_addroundkey_wire;

            r5_subbytes_reg <= r5_subbytes_wire;
            r5_shiftrows_reg <= r5_shiftrows_wire;
            r5_mixcolumns_reg <= r5_mixcolumns_wire;
            r5_addroundkey_reg <= r5_addroundkey_wire;

            r6_subbytes_reg <= r6_subbytes_wire;
            r6_shiftrows_reg <= r6_shiftrows_wire;
            r6_mixcolumns_reg <= r6_mixcolumns_wire;
            r6_addroundkey_reg <= r6_addroundkey_wire;

            r7_subbytes_reg <= r7_subbytes_wire;
            r7_shiftrows_reg <= r7_shiftrows_wire;
            r7_mixcolumns_reg <= r7_mixcolumns_wire;
            r7_addroundkey_reg <= r7_addroundkey_wire;

            r8_subbytes_reg <= r8_subbytes_wire;
            r8_shiftrows_reg <= r8_shiftrows_wire;
            r8_mixcolumns_reg <= r8_mixcolumns_wire;
            r8_addroundkey_reg <= r8_addroundkey_wire;

            r9_subbytes_reg <= r9_subbytes_wire;
            r9_shiftrows_reg <= r9_shiftrows_wire;
            r9_mixcolumns_reg <= r9_mixcolumns_wire;
            r9_addroundkey_reg <= r9_addroundkey_wire;

            r10_subbytes_reg <= r10_subbytes_wire;
            r10_shiftrows_reg <= r10_shiftrows_wire;
            r10_addroundkey_reg <= r10_addroundkey_wire;


            r0_invaddroundkey_reg <= r0_invaddroundkey_out;
            r1_invshiftrows_reg <= r1_invshiftrows_out;
            r1_invsubbytes_reg <= r1_invsubbytes_out;
            r1_invaddroundkey_reg <= r1_invaddroundkey_out;
            r1_invmixcolumns_reg <= r1_invmixcolumns_out;
            r2_invshiftrows_reg <= r2_invshiftrows_out;
            r2_invsubbytes_reg <= r2_invsubbytes_out;
            r2_invaddroundkey_reg <= r2_invaddroundkey_out;
            r2_invmixcolumns_reg <= r2_invmixcolumns_out;
            r3_invshiftrows_reg <= r3_invshiftrows_out;
            r3_invsubbytes_reg <= r3_invsubbytes_out;
            r3_invaddroundkey_reg <= r3_invaddroundkey_out;
            r3_invmixcolumns_reg <= r3_invmixcolumns_out;
            r4_invshiftrows_reg <= r4_invshiftrows_out;
            r4_invsubbytes_reg <= r4_invsubbytes_out;
            r4_invaddroundkey_reg <= r4_invaddroundkey_out;
            r4_invmixcolumns_reg <= r4_invmixcolumns_out;
            r5_invshiftrows_reg <= r5_invshiftrows_out;
            r5_invsubbytes_reg <= r5_invsubbytes_out;
            r5_invaddroundkey_reg <= r5_invaddroundkey_out;
            r5_invmixcolumns_reg <= r5_invmixcolumns_out;
            r6_invshiftrows_reg <= r6_invshiftrows_out;
            r6_invsubbytes_reg <= r6_invsubbytes_out;
            r6_invaddroundkey_reg <= r6_invaddroundkey_out;
            r6_invmixcolumns_reg <= r6_invmixcolumns_out;
            r7_invshiftrows_reg <= r7_invshiftrows_out;
            r7_invsubbytes_reg <= r7_invsubbytes_out;
            r7_invaddroundkey_reg <= r7_invaddroundkey_out;
            r7_invmixcolumns_reg <= r7_invmixcolumns_out;
            r8_invshiftrows_reg <= r8_invshiftrows_out;
            r8_invsubbytes_reg <= r8_invsubbytes_out;
            r8_invaddroundkey_reg <= r8_invaddroundkey_out;
            r8_invmixcolumns_reg <= r8_invmixcolumns_out;
            r9_invshiftrows_reg <= r9_invshiftrows_out;
            r9_invsubbytes_reg <= r9_invsubbytes_out;
            r9_invaddroundkey_reg <= r9_invaddroundkey_out;
            r9_invmixcolumns_reg <= r9_invmixcolumns_out;
            r10_invshiftrows_reg <= r10_invshiftrows_out;
            r10_invsubbytes_reg <= r10_invsubbytes_out;
            r10_invaddroundkey_reg <= r10_invaddroundkey_out;

            tx_dv <= 0;

            if (!sending) begin
                if (rx_dv) begin
                    if (byte_cnt == 0)
                        mode_reg <= rx_byte[0];
                    else if (byte_cnt <= 16)
                        key_buf <= {key_buf[119:0], rx_byte};
                    else
                        data_buf <= {data_buf[119:0], rx_byte};
                    byte_cnt <= byte_cnt + 1;
                    if (byte_cnt == 32) begin
                        sending <= 1;
                        send_cnt <= 0;
                        step <= 0;
                        round_num <= 0;
                        byte_cnt <= 0;
                        key_exp_start <= 1;
                        last_addroundkey <= 0;
                    end
                end
            end else begin
                key_exp_start <= 0;

                if (!tx_active && !tx_dv && key_exp_done) begin
                    if (mode_reg == 0) begin 
                        case(round_num)
                            0: begin
                                case(step)
                                    0: tx_byte <= r0_addroundkey_out[127 - 8*send_cnt -: 8]; // input
                                    1: tx_byte <= key_buf[127 - 8*send_cnt -: 8]; // k_sch
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            1: begin
                                case(step)
                                    0: tx_byte <= r1_subbytes_reg[127 - 8*send_cnt -: 8]; // start
                                    1: tx_byte <= r1_shiftrows_reg[127 - 8*send_cnt -: 8]; // s_row
                                    2: tx_byte <= r1_mixcolumns_reg[127 - 8*send_cnt -: 8]; // m_col
                                    3: tx_byte <= round_keys_out[1279 - 8*send_cnt -: 8]; // k_sch
                                    4: tx_byte <= r1_addroundkey_reg[127 - 8*send_cnt -: 8]; // output
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            2: begin
                                case(step)
                                    0: tx_byte <= r2_subbytes_reg[127 - 8*send_cnt -: 8];
                                    1: tx_byte <= r2_shiftrows_reg[127 - 8*send_cnt -: 8];
                                    2: tx_byte <= r2_mixcolumns_reg[127 - 8*send_cnt -: 8];
                                    3: tx_byte <= round_keys_out[1151 - 8*send_cnt -: 8];
                                    4: tx_byte <= r2_addroundkey_reg[127 - 8*send_cnt -: 8];
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            3: begin
                                case(step)
                                    0: tx_byte <= r3_subbytes_reg[127 - 8*send_cnt -: 8];
                                    1: tx_byte <= r3_shiftrows_reg[127 - 8*send_cnt -: 8];
                                    2: tx_byte <= r3_mixcolumns_reg[127 - 8*send_cnt -: 8];
                                    3: tx_byte <= round_keys_out[1023 - 8*send_cnt -: 8];
                                    4: tx_byte <= r3_addroundkey_reg[127 - 8*send_cnt -: 8];
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            4: begin
                                case(step)
                                    0: tx_byte <= r4_subbytes_reg[127 - 8*send_cnt -: 8];
                                    1: tx_byte <= r4_shiftrows_reg[127 - 8*send_cnt -: 8];
                                    2: tx_byte <= r4_mixcolumns_reg[127 - 8*send_cnt -: 8];
                                    3: tx_byte <= round_keys_out[895 - 8*send_cnt -: 8];
                                    4: tx_byte <= r4_addroundkey_reg[127 - 8*send_cnt -: 8];
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            5: begin
                                case(step)
                                    0: tx_byte <= r5_subbytes_reg[127 - 8*send_cnt -: 8];
                                    1: tx_byte <= r5_shiftrows_reg[127 - 8*send_cnt -: 8];
                                    2: tx_byte <= r5_mixcolumns_reg[127 - 8*send_cnt -: 8];
                                    3: tx_byte <= round_keys_out[767 - 8*send_cnt -: 8];
                                    4: tx_byte <= r5_addroundkey_reg[127 - 8*send_cnt -: 8];
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            6: begin
                                case(step)
                                    0: tx_byte <= r6_subbytes_reg[127 - 8*send_cnt -: 8];
                                    1: tx_byte <= r6_shiftrows_reg[127 - 8*send_cnt -: 8];
                                    2: tx_byte <= r6_mixcolumns_reg[127 - 8*send_cnt -: 8];
                                    3: tx_byte <= round_keys_out[639 - 8*send_cnt -: 8];
                                    4: tx_byte <= r6_addroundkey_reg[127 - 8*send_cnt -: 8];
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            7: begin
                                case(step)
                                    0: tx_byte <= r7_subbytes_reg[127 - 8*send_cnt -: 8];
                                    1: tx_byte <= r7_shiftrows_reg[127 - 8*send_cnt -: 8];
                                    2: tx_byte <= r7_mixcolumns_reg[127 - 8*send_cnt -: 8];
                                    3: tx_byte <= round_keys_out[511 - 8*send_cnt -: 8];
                                    4: tx_byte <= r7_addroundkey_reg[127 - 8*send_cnt -: 8];
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            8: begin
                                case(step)
                                    0: tx_byte <= r8_subbytes_reg[127 - 8*send_cnt -: 8];
                                    1: tx_byte <= r8_shiftrows_reg[127 - 8*send_cnt -: 8];
                                    2: tx_byte <= r8_mixcolumns_reg[127 - 8*send_cnt -: 8];
                                    3: tx_byte <= round_keys_out[383 - 8*send_cnt -: 8];
                                    4: tx_byte <= r8_addroundkey_reg[127 - 8*send_cnt -: 8];
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            9: begin
                                case(step)
                                    0: tx_byte <= r9_subbytes_reg[127 - 8*send_cnt -: 8];
                                    1: tx_byte <= r9_shiftrows_reg[127 - 8*send_cnt -: 8];
                                    2: tx_byte <= r9_mixcolumns_reg[127 - 8*send_cnt -: 8];
                                    3: tx_byte <= round_keys_out[255 - 8*send_cnt -: 8];
                                    4: tx_byte <= r9_addroundkey_reg[127 - 8*send_cnt -: 8];
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            10: begin
                                case(step)
                                    0: tx_byte <= r10_subbytes_reg[127 - 8*send_cnt -: 8]; // start
                                    1: tx_byte <= r10_shiftrows_reg[127 - 8*send_cnt -: 8]; // s_row
                                    2: tx_byte <= round_keys_out[127 - 8*send_cnt -: 8]; // k_sch
                                    3: tx_byte <= r10_addroundkey_reg[127 - 8*send_cnt -: 8]; // output
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            default: tx_byte <= 8'h00;
                        endcase
                    end else begin 
                        case(round_num)
                            0: begin
                                case(step)
                                    0: tx_byte <= data_buf[127 - 8*send_cnt -: 8]; // iinput
                                    1: tx_byte <= r0_invaddroundkey_reg[127 - 8*send_cnt -: 8]; // ik_sch
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            1: begin
                                case(step)
                                    1: tx_byte <= r0_invaddroundkey_reg[127 - 8*send_cnt -: 8]; 
                                    2: tx_byte <= r1_invshiftrows_reg[127 - 8*send_cnt -: 8]; 
                                    3: tx_byte <= r1_invsubbytes_reg[127 - 8*send_cnt -: 8]; 
                                    4: tx_byte <= round_keys_out[255 - 8*send_cnt -: 8]; 
                                    5: tx_byte <= r1_invaddroundkey_reg[127 - 8*send_cnt -: 8]; 
                                    6: tx_byte <= r1_invmixcolumns_reg[127 - 8*send_cnt -: 8]; 
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            2: begin
                                case(step)
                                    1: tx_byte <= r1_invmixcolumns_reg[127 - 8*send_cnt -: 8]; 
                                    2: tx_byte <= r2_invshiftrows_reg[127 - 8*send_cnt -: 8];
                                    3: tx_byte <= r2_invsubbytes_reg[127 - 8*send_cnt -: 8]; 
                                    4: tx_byte <= round_keys_out[383 - 8*send_cnt -: 8]; 
                                    5: tx_byte <= r2_invaddroundkey_reg[127 - 8*send_cnt -: 8];
                                    6: tx_byte <= r2_invmixcolumns_reg[127 - 8*send_cnt -: 8]; 
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            3: begin
                                case(step)
                                    1: tx_byte <= r2_invmixcolumns_reg[127 - 8*send_cnt -: 8]; 
                                    2: tx_byte <= r3_invshiftrows_reg[127 - 8*send_cnt -: 8];
                                    3: tx_byte <= r3_invsubbytes_reg[127 - 8*send_cnt -: 8]; 
                                    4: tx_byte <= round_keys_out[511 - 8*send_cnt -: 8]; 
                                    5: tx_byte <= r3_invaddroundkey_reg[127 - 8*send_cnt -: 8]; 
                                    6: tx_byte <= r3_invmixcolumns_reg[127 - 8*send_cnt -: 8]; 
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            4: begin
                                case(step)
                                    1: tx_byte <= r3_invmixcolumns_reg[127 - 8*send_cnt -: 8];
                                    2: tx_byte <= r4_invshiftrows_reg[127 - 8*send_cnt -: 8]; 
                                    3: tx_byte <= r4_invsubbytes_reg[127 - 8*send_cnt -: 8];
                                    4: tx_byte <= round_keys_out[639 - 8*send_cnt -: 8]; 
                                    5: tx_byte <= r4_invaddroundkey_reg[127 - 8*send_cnt -: 8]; 
                                    6: tx_byte <= r4_invmixcolumns_reg[127 - 8*send_cnt -: 8]; 
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            5: begin
                                case(step)
                                    1: tx_byte <= r4_invmixcolumns_reg[127 - 8*send_cnt -: 8];
                                    2: tx_byte <= r5_invshiftrows_reg[127 - 8*send_cnt -: 8]; 
                                    3: tx_byte <= r5_invsubbytes_reg[127 - 8*send_cnt -: 8]; 
                                    4: tx_byte <= round_keys_out[767 - 8*send_cnt -: 8]; 
                                    5: tx_byte <= r5_invaddroundkey_reg[127 - 8*send_cnt -: 8];
                                    6: tx_byte <= r5_invmixcolumns_reg[127 - 8*send_cnt -: 8]; 
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            6: begin
                                case(step)
                                    1: tx_byte <= r5_invmixcolumns_reg[127 - 8*send_cnt -: 8];
                                    2: tx_byte <= r6_invshiftrows_reg[127 - 8*send_cnt -: 8]; 
                                    3: tx_byte <= r6_invsubbytes_reg[127 - 8*send_cnt -: 8]; 
                                    4: tx_byte <= round_keys_out[895 - 8*send_cnt -: 8]; 
                                    5: tx_byte <= r6_invaddroundkey_reg[127 - 8*send_cnt -: 8]; 
                                    6: tx_byte <= r6_invmixcolumns_reg[127 - 8*send_cnt -: 8]; 
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            7: begin
                                case(step)
                                    1: tx_byte <= r6_invmixcolumns_reg[127 - 8*send_cnt -: 8]; 
                                    2: tx_byte <= r7_invshiftrows_reg[127 - 8*send_cnt -: 8]; 
                                    3: tx_byte <= r7_invsubbytes_reg[127 - 8*send_cnt -: 8]; 
                                    4: tx_byte <= round_keys_out[1023 - 8*send_cnt -: 8]; 
                                    5: tx_byte <= r7_invaddroundkey_reg[127 - 8*send_cnt -: 8]; 
                                    6: tx_byte <= r7_invmixcolumns_reg[127 - 8*send_cnt -: 8];
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            8: begin
                                case(step)
                                    1: tx_byte <= r7_invmixcolumns_reg[127 - 8*send_cnt -: 8]; 
                                    2: tx_byte <= r8_invshiftrows_reg[127 - 8*send_cnt -: 8]; 
                                    3: tx_byte <= r8_invsubbytes_reg[127 - 8*send_cnt -: 8];
                                    4: tx_byte <= round_keys_out[1151 - 8*send_cnt -: 8]; 
                                    5: tx_byte <= r8_invaddroundkey_reg[127 - 8*send_cnt -: 8];
                                    6: tx_byte <= r8_invmixcolumns_reg[127 - 8*send_cnt -: 8];
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            9: begin
                                case(step)
                                    1: tx_byte <= r8_invmixcolumns_reg[127 - 8*send_cnt -: 8]; 
                                    2: tx_byte <= r9_invshiftrows_reg[127 - 8*send_cnt -: 8];
                                    3: tx_byte <= r9_invsubbytes_reg[127 - 8*send_cnt -: 8]; 
                                    4: tx_byte <= round_keys_out[1279 - 8*send_cnt -: 8]; 
                                    5: tx_byte <= r9_invaddroundkey_reg[127 - 8*send_cnt -: 8];
                                    6: tx_byte <= r9_invmixcolumns_reg[127 - 8*send_cnt -: 8]; 
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            10: begin
                                case(step)
                                    1: tx_byte <= r9_invmixcolumns_reg[127 - 8*send_cnt -: 8]; 
                                    2: tx_byte <= r10_invshiftrows_reg[127 - 8*send_cnt -: 8]; 
                                    3: tx_byte <= r10_invsubbytes_reg[127 - 8*send_cnt -: 8];
                                    4: tx_byte <= round_keys_out[1407 - 8*send_cnt -: 8]; 
                                    5: tx_byte <= r10_invaddroundkey_reg[127 - 8*send_cnt -: 8]; 
                                    default: tx_byte <= 8'h00;
                                endcase
                            end
                            default: tx_byte <= 8'h00;
                        endcase
                    end

                    tx_dv <= 1;
                    send_cnt <= send_cnt + 1;

                    if (send_cnt == 15) begin
                        send_cnt <= 0;
                        if (mode_reg == 0) begin 
                            if ((round_num == 0 && step == 1) || (round_num >= 1 && step == 4 && round_num <= 9) || (round_num == 10 && step == 3)) begin
                                step <= 0;
                                round_num <= round_num + 1;
                                if (round_num == 10) begin
                                    sending <= 0; 
                                end
                            end else begin
                                step <= step + 1;
                            end
                        end else begin 
                            if ((round_num == 0 && step == 1) || (round_num >= 1 && round_num <= 9 && step == 6) || (round_num == 10 && step == 5)) begin
                                step <= 0;
                                round_num <= round_num + 1;
                                if (round_num == 10) begin
                                    sending <= 0; 
                                end
                            end else begin
                                step <= step + 1;
                            end
                        end
                    end
                end
            end
        end
    end

endmodule



module aes_encryption_finale(
    input [127:0] initial_msg,
    input [127:0] key,
    output [127:0] xor_msg
);
    assign xor_msg = initial_msg ^ key;
endmodule




module aes_key_expansion(
    input wire clk,
    input wire rst,
    input wire start,
    input wire [127:0] key_in,
    output reg [1407:0] round_keys_out, 
    output reg done
);

   
    reg [31:0] rcon [0:9];
    initial begin
        rcon[0] = 32'h01000000;
        rcon[1] = 32'h02000000;
        rcon[2] = 32'h04000000;
        rcon[3] = 32'h08000000;
        rcon[4] = 32'h10000000;
        rcon[5] = 32'h20000000;
        rcon[6] = 32'h40000000;
        rcon[7] = 32'h80000000;
        rcon[8] = 32'h1b000000;
        rcon[9] = 32'h36000000;
    end

    
    reg [7:0] sbox [0:255];
    initial $readmemh("D:/Licenta/Licenta/PROIECT LICENTA  FINAL/project_1/sbox_mem.txt", sbox);

 
    function [31:0] RotWord;
        input [31:0] w;
        begin
            RotWord = {w[23:0], w[31:24]};
        end
    endfunction

    function [31:0] SubWord;
        input [31:0] w;
        begin
            SubWord = {sbox[w[31:24]], sbox[w[23:16]], sbox[w[15:8]], sbox[w[7:0]]};
        end
    endfunction

    reg [31:0] w [0:43];  

    reg [5:0] i;
    reg busy;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            i <= 0;
            busy <= 0;
            done <= 0;
            round_keys_out <= 0;
        end else if (start && !busy) begin
            w[0] <= key_in[127:96];
            w[1] <= key_in[95:64];
            w[2] <= key_in[63:32];
            w[3] <= key_in[31:0];
            i <= 4;
            busy <= 1;
            done <= 0;
        end else if (busy) begin
            if (i < 44) begin
                if (i % 4 == 0)
                    w[i] <= w[i-4] ^ SubWord(RotWord(w[i-1])) ^ rcon[(i/4)-1];
                else
                    w[i] <= w[i-4] ^ w[i-1];
                i <= i + 1;
            end else begin
                round_keys_out = {
                    w[0],  w[1],  w[2],  w[3],
                    w[4],  w[5],  w[6],  w[7],
                    w[8],  w[9],  w[10], w[11],
                    w[12], w[13], w[14], w[15],
                    w[16], w[17], w[18], w[19],
                    w[20], w[21], w[22], w[23],
                    w[24], w[25], w[26], w[27],
                    w[28], w[29], w[30], w[31],
                    w[32], w[33], w[34], w[35],
                    w[36], w[37], w[38], w[39],
                    w[40], w[41], w[42], w[43]
                };

                done <= 1;
                busy <= 0;
            end
        end
    end

endmodule



module aes_sub_bytes(state_in, state_out);
    input [127:0] state_in;
    output reg [127:0] state_out;
    
    reg [7:0] sbox [0:255];
    
    initial begin
        $readmemh("D:/Licenta/Licenta/PROIECT LICENTA  FINAL/project_1/sbox_mem.txt", sbox);
    end
    
    integer i;
    always@(*)
    begin
        for(i=0; i<16; i=i+1)
        begin
            state_out[(i*8)+7 -: 8] = sbox[state_in[(i*8)+7 -: 8]];


        end
    
    end  
    
endmodule



module aes_shift_rows(
    input [127:0] state_in,
    output [127:0] state_out
);



assign state_out = 
{
    state_in[127:120], state_in[87:80], state_in[47:40], state_in[7:0],
    state_in[95:88], state_in[55:48], state_in[15:8], state_in[103:96],
    state_in[63:56], state_in[23:16], state_in[111:104], state_in[71:64],
    state_in[31:24], state_in[119:112], state_in[79:72], state_in[39:32]
};

endmodule





module aes_mix_columns(state_in, state_out);
    input wire [127:0] state_in;
    output reg [127:0] state_out;
    

    function [7:0] gmul2;
        input [7:0] b;
        begin
            if(b[7] == 1)
                gmul2 = (b << 1) ^ 8'h1B; 
            else
                gmul2 = b << 1;
        end
    
    endfunction
    
    
    function [7:0] gmul3;
        input [7:0] b;
        begin
            gmul3 = gmul2(b) ^ b;
        end
    endfunction
        
        reg [7:0] s0, s1, s2, s3;
                    
        always @(*)
        begin
           
            s0 = state_in[127:120];
            s1 = state_in[119:112];
            s2 = state_in[111:104];
            s3 = state_in[103:96];
            state_out[127:120] = gmul2(s0) ^ gmul3(s1) ^ s2 ^ s3;
            state_out[119:112] = s0 ^ gmul2(s1) ^ gmul3(s2) ^ s3;
            state_out[111:104] = s0 ^ s1 ^ gmul2(s2) ^ gmul3(s3);
            state_out[103:96] = gmul3(s0) ^ s1 ^ s2 ^ gmul2(s3);
            
            
            s0 = state_in[95:88];
            s1 = state_in[87:80];
            s2 = state_in[79:72];
            s3 = state_in[71:64];
            state_out[95:88] = gmul2(s0) ^ gmul3(s1) ^ s2 ^ s3;
            state_out[87:80] = s0 ^ gmul2(s1) ^ gmul3(s2) ^ s3;
            state_out[79:72] = s0 ^ s1 ^ gmul2(s2) ^ gmul3(s3);
            state_out[71:64] = gmul3(s0) ^ s1 ^ s2 ^ gmul2(s3);
            
            
            s0 = state_in[63:56];
            s1 = state_in[55:48];
            s2 = state_in[47:40];
            s3 = state_in[39:32];
            state_out[63:56] = gmul2(s0) ^ gmul3(s1) ^ s2 ^ s3;
            state_out[55:48] = s0 ^ gmul2(s1) ^ gmul3(s2) ^ s3;
            state_out[47:40] = s0 ^ s1 ^ gmul2(s2) ^ gmul3(s3);
            state_out[39:32] = gmul3(s0) ^ s1 ^ s2 ^ gmul2(s3);
            
            
            s0 = state_in[31:24];
            s1 = state_in[23:16];
            s2 = state_in[15:8];
            s3 = state_in[7:0];
            state_out[31:24] = gmul2(s0) ^ gmul3(s1) ^ s2 ^ s3;
            state_out[23:16] = s0 ^ gmul2(s1) ^ gmul3(s2) ^ s3;
            state_out[15:8] = s0 ^ s1 ^ gmul2(s2) ^ gmul3(s3);
            state_out[7:0] = gmul3(s0) ^ s1 ^ s2 ^ gmul2(s3);
        
        
        end
    
endmodule




module aes_add_round_key(state_in, round_key, state_out);
    input wire [127:0] state_in;
    input wire [127:0] round_key;
    output wire [127:0] state_out;
    
    assign state_out = state_in ^ round_key;
    
    
endmodule







module aes_sub_bytes_inv(state_in, state_out);
    input [127:0] state_in;
    output reg [127:0] state_out;
    
    reg [7:0] inv_sbox [0:255];
    
    initial begin
        $readmemh("D:/Licenta/Licenta/PROIECT LICENTA  FINAL/project_1/inv_sbox_mem.txt", inv_sbox);
    end
    
    integer i;
    always@(*)
    begin
        for(i=0; i<16; i=i+1)
        begin
            state_out[(i+1)*8-1 -: 8] = inv_sbox[state_in[(i+1)*8-1 -: 8]];

          
        end
    
    end  
    

endmodule 




module aes_shift_rows_inv( 
    input [127:0] state_in,
    output [127:0] state_out
);


assign state_out = {
    state_in[127:120], 
    state_in[23:16],   
    state_in[47:40],   
    state_in[71:64],   

    state_in[95:88],  
    state_in[119:112], 
    state_in[15:8],   
    state_in[39:32],  

    state_in[63:56],
    state_in[87:80],
    state_in[111:104],
    state_in[7:0],

    state_in[31:24],
    state_in[55:48],
    state_in[79:72],
    state_in[103:96]
};

endmodule


module aes_mix_columns_inv(
    input wire [127:0] state_in,
    output reg [127:0] state_out
);

    function [7:0] gmul;
        input [7:0] a, b;
        reg [7:0] p;
        integer i;
        begin
            p = 0;
            for (i = 0; i < 8; i = i + 1) begin
                if (b[0])
                    p = p ^ a;
                if (a[7])
                    a = (a << 1) ^ 8'h1b;
                else
                    a = a << 1;
                b = b >> 1;
            end
            gmul = p;
        end
    endfunction

    integer i;
    reg [7:0] s [0:15];
    reg [7:0] r [0:15];

    always @(*) begin
        for (i = 0; i < 16; i = i + 1)
            s[i] = state_in[127 - 8*i -: 8];

        for (i = 0; i < 4; i = i + 1) begin
            r[4*i + 0] = gmul(s[4*i+0], 8'h0e) ^ gmul(s[4*i+1], 8'h0b) ^ gmul(s[4*i+2], 8'h0d) ^ gmul(s[4*i+3], 8'h09);
            r[4*i + 1] = gmul(s[4*i+0], 8'h09) ^ gmul(s[4*i+1], 8'h0e) ^ gmul(s[4*i+2], 8'h0b) ^ gmul(s[4*i+3], 8'h0d);
            r[4*i + 2] = gmul(s[4*i+0], 8'h0d) ^ gmul(s[4*i+1], 8'h09) ^ gmul(s[4*i+2], 8'h0e) ^ gmul(s[4*i+3], 8'h0b);
            r[4*i + 3] = gmul(s[4*i+0], 8'h0b) ^ gmul(s[4*i+1], 8'h0d) ^ gmul(s[4*i+2], 8'h09) ^ gmul(s[4*i+3], 8'h0e);
        end


        for (i = 0; i < 16; i = i + 1)
            state_out[127 - 8*i -: 8] = r[i];
    end
endmodule


       
       
       












module uart_rx 
  #(parameter CLKS_PER_BIT = 10416)
  (
   input        i_Clock,
   input        i_Rx_Serial,
   output       o_Rx_DV,
   output [7:0] o_Rx_Byte
   );

  parameter s_IDLE         = 3'b000;
  parameter s_RX_START_BIT = 3'b001;
  parameter s_RX_DATA_BITS = 3'b010;
  parameter s_RX_STOP_BIT  = 3'b011;
  parameter s_CLEANUP      = 3'b100;

  reg        r_Rx_Data_R = 1'b1;
  reg        r_Rx_Data   = 1'b1;
  reg [13:0] r_Clock_Count = 0;   
  reg [2:0]  r_Bit_Index   = 0;
  reg [7:0]  r_Rx_Byte     = 0;
  reg        r_Rx_DV       = 0;
  reg [2:0]  r_SM_Main     = 0;

  always @(posedge i_Clock)
    begin
      r_Rx_Data_R <= i_Rx_Serial;
      r_Rx_Data   <= r_Rx_Data_R;
    end

  always @(posedge i_Clock)
    begin
      case (r_SM_Main)
        s_IDLE :
          begin
            r_Rx_DV       <= 1'b0;
            r_Clock_Count <= 0;
            r_Bit_Index   <= 0;

            if (r_Rx_Data == 1'b0)
              r_SM_Main <= s_RX_START_BIT;
          end

        s_RX_START_BIT :
          begin
            if (r_Clock_Count == (CLKS_PER_BIT-1)/2)
              begin
                if (r_Rx_Data == 1'b0)
                  begin
                    r_Clock_Count <= 0;
                    r_SM_Main     <= s_RX_DATA_BITS;
                  end
                else
                  r_SM_Main <= s_IDLE;
              end
            else
              r_Clock_Count <= r_Clock_Count + 1;
          end

        s_RX_DATA_BITS :
          begin
            if (r_Clock_Count < CLKS_PER_BIT-1)
              r_Clock_Count <= r_Clock_Count + 1;
            else
              begin
                r_Clock_Count         <= 0;
                r_Rx_Byte[r_Bit_Index] <= r_Rx_Data;

                if (r_Bit_Index < 7)
                  r_Bit_Index <= r_Bit_Index + 1;
                else
                  begin
                    r_Bit_Index <= 0;
                    r_SM_Main   <= s_RX_STOP_BIT;
                  end
              end
          end

        s_RX_STOP_BIT :
          begin
            if (r_Clock_Count < CLKS_PER_BIT-1)
              r_Clock_Count <= r_Clock_Count + 1;
            else
              begin
                r_Rx_DV       <= 1'b1;
                r_Clock_Count <= 0;
                r_SM_Main     <= s_CLEANUP;
              end
          end

        s_CLEANUP :
          begin
            r_SM_Main <= s_IDLE;
            r_Rx_DV   <= 1'b0;
          end

        default :
          r_SM_Main <= s_IDLE;
      endcase
    end

  assign o_Rx_DV   = r_Rx_DV;
  assign o_Rx_Byte = r_Rx_Byte;

endmodule






module uart_tx 
  #(parameter CLKS_PER_BIT = 10416)
  (
   input        i_Clock,
   input        i_Tx_DV,
   input  [7:0] i_Tx_Byte, 
   output       o_Tx_Active,
   output reg   o_Tx_Serial,
   output       o_Tx_Done
   );

  parameter s_IDLE         = 3'b000;
  parameter s_TX_START_BIT = 3'b001;
  parameter s_TX_DATA_BITS = 3'b010;
  parameter s_TX_STOP_BIT  = 3'b011;
  parameter s_CLEANUP      = 3'b100;

  reg [2:0] r_SM_Main      = 0;
  reg [13:0] r_Clock_Count = 0;   
  reg [2:0] r_Bit_Index    = 0;
  reg [7:0] r_Tx_Data      = 0;
  reg       r_Tx_Done      = 0;
  reg       r_Tx_Active    = 0;

  always @(posedge i_Clock)
    begin
      case (r_SM_Main)
        s_IDLE :
          begin
            o_Tx_Serial   <= 1'b1;
            r_Tx_Done     <= 1'b0;
            r_Clock_Count <= 0;
            r_Bit_Index   <= 0;

            if (i_Tx_DV == 1'b1)
              begin
                r_Tx_Active <= 1'b1;
                r_Tx_Data   <= i_Tx_Byte;
                r_SM_Main   <= s_TX_START_BIT;
              end
            else
              r_SM_Main <= s_IDLE;
          end

        s_TX_START_BIT :
          begin
            o_Tx_Serial <= 1'b0;

            if (r_Clock_Count < CLKS_PER_BIT-1)
              r_Clock_Count <= r_Clock_Count + 1;
            else
              begin
                r_Clock_Count <= 0;
                r_SM_Main     <= s_TX_DATA_BITS;
              end
          end

        s_TX_DATA_BITS :
          begin
            o_Tx_Serial <= r_Tx_Data[r_Bit_Index];

            if (r_Clock_Count < CLKS_PER_BIT-1)
              r_Clock_Count <= r_Clock_Count + 1;
            else
              begin
                r_Clock_Count <= 0;

                if (r_Bit_Index < 7)
                  r_Bit_Index <= r_Bit_Index + 1;
                else
                  begin
                    r_Bit_Index <= 0;
                    r_SM_Main   <= s_TX_STOP_BIT;
                  end
              end
          end

        s_TX_STOP_BIT :
          begin
            o_Tx_Serial <= 1'b1;

            if (r_Clock_Count < CLKS_PER_BIT-1)
              r_Clock_Count <= r_Clock_Count + 1;
            else
              begin
                r_Tx_Done     <= 1'b1;
                r_Clock_Count <= 0;
                r_SM_Main     <= s_CLEANUP;
                r_Tx_Active   <= 1'b0;
              end
          end

        s_CLEANUP :
          begin
            r_Tx_Done <= 1'b1;
            r_SM_Main <= s_IDLE;
          end

        default :
          r_SM_Main <= s_IDLE;
      endcase
    end

  assign o_Tx_Active = r_Tx_Active;
  assign o_Tx_Done   = r_Tx_Done;

endmodule