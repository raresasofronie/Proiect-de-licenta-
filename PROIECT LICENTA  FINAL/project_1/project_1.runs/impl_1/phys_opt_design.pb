
B
Command: %s
53*	vivadotcl2
phys_opt_designZ4-113h px� 
~
@Attempting to get a license for feature '%s' and/or device '%s'
308*common2
Implementation2
xc7s50Z17-347h px� 
n
0Got license for feature '%s' and/or device '%s'
310*common2
Implementation2
xc7s50Z17-349h px� 
R

Starting %s Task
103*constraints2
Initial Update TimingZ18-103h px� 
~

%s
*constraints2^
\Time (s): cpu = 00:00:06 ; elapsed = 00:00:03 . Memory (MB): peak = 3317.512 ; gain = 11.559h px� 
�
^PhysOpt_Tcl_Interface Runtime Before Starting Physical Synthesis Task | CPU: %ss |  WALL: %ss
566*	vivadotcl2
6.002
3.65Z4-1435h px� 
�
I%sTime (s): cpu = %s ; elapsed = %s . Memory (MB): peak = %s ; gain = %s
268*common2
Netlist sorting complete. 2

00:00:002
00:00:00.0042

3317.5122
0.000Z17-268h px� 
O

Starting %s Task
103*constraints2
Physical SynthesisZ18-103h px� 
^

Phase %s%s
101*constraints2
1 2#
!Physical Synthesis InitializationZ18-101h px� 
n
EMultithreading enabled for phys_opt_design using a maximum of %s CPUs380*physynth2
2Z32-721h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.2282
-135979.571Z32-619h px� 
[
%s*common2B
@Phase 1 Physical Synthesis Initialization | Checksum: 1dc317dee
h px� 
}

%s
*constraints2]
[Time (s): cpu = 00:00:02 ; elapsed = 00:00:01 . Memory (MB): peak = 3317.512 ; gain = 0.000h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.2282
-135979.571Z32-619h px� 
V

Phase %s%s
101*constraints2
2 2
DSP Register OptimizationZ18-101h px� 
j
FNo candidate cells for DSP register optimization found in the design.
274*physynthZ32-456h px� 
�
aEnd %s Pass. Optimized %s %s. Created %s new %s, deleted %s existing %s and moved %s existing %s
415*physynth2
22
02
net or cell2
02
cell2
02
cell2
02
cellZ32-775h px� 
S
%s*common2:
8Phase 2 DSP Register Optimization | Checksum: 1dc317dee
h px� 
}

%s
*constraints2]
[Time (s): cpu = 00:00:02 ; elapsed = 00:00:02 . Memory (MB): peak = 3317.512 ; gain = 0.000h px� 
W

Phase %s%s
101*constraints2
3 2
Critical Path OptimizationZ18-101h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.2282
-135979.571Z32-619h px� 
�
(Processed net %s.  Re-placed instance %s337*physynth26
r10_invsubbytes_reg[111]r10_invsubbytes_reg[111]2>
r10_invsubbytes_reg_reg[111]	r10_invsubbytes_reg_reg[111]8Z32-663h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth26
r10_invsubbytes_reg[111]r10_invsubbytes_reg[111]8Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.2282
-135978.684Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2:
r10_invaddroundkey_reg[93]r10_invaddroundkey_reg[93]8Z32-702h px� 
�
(Processed net %s.  Re-placed instance %s337*physynth2
data_buf[56]data_buf[56]2&
data_buf_reg[56]	data_buf_reg[56]8Z32-663h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2
data_buf[56]data_buf[56]8Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.2272
-135975.497Z32-619h px� 
�
(Processed net %s.  Re-placed instance %s337*physynth24
r10_invsubbytes_reg[33]r10_invsubbytes_reg[33]2<
r10_invsubbytes_reg_reg[33]	r10_invsubbytes_reg_reg[33]8Z32-663h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth24
r10_invsubbytes_reg[33]r10_invsubbytes_reg[33]8Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.2262
-135974.609Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth24
r10_addroundkey_reg[66]r10_addroundkey_reg[66]8Z32-702h px� 
�
(Processed net %s.  Re-placed instance %s337*physynth2
key_buf[121]key_buf[121]2&
key_buf_reg[121]	key_buf_reg[121]8Z32-663h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2
key_buf[121]key_buf[121]8Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.2252
-135956.565Z32-619h px� 
�
(Processed net %s.  Re-placed instance %s337*physynth22
r10_invsubbytes_reg[7]r10_invsubbytes_reg[7]2:
r10_invsubbytes_reg_reg[7]	r10_invsubbytes_reg_reg[7]8Z32-663h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth22
r10_invsubbytes_reg[7]r10_invsubbytes_reg[7]8Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.2242
-135955.677Z32-619h px� 
�
(Processed net %s.  Re-placed instance %s337*physynth2b
.key_expansion_unit/round_keys_out_reg_n_0_[48].key_expansion_unit/round_keys_out_reg_n_0_[48]2X
)key_expansion_unit/round_keys_out_reg[48]	)key_expansion_unit/round_keys_out_reg[48]8Z32-663h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2b
.key_expansion_unit/round_keys_out_reg_n_0_[48].key_expansion_unit/round_keys_out_reg_n_0_[48]8Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.2242
-135955.546Z32-619h px� 
p
'Processed net %s. Replicated %s times.
81*physynth2
data_buf[88]data_buf[88]2
18Z32-81h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2
data_buf[88]data_buf[88]8Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.2192
-135951.777Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2@
r10_invaddroundkey_reg__0[34]r10_invaddroundkey_reg__0[34]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2b
.key_expansion_unit/round_keys_out_reg_n_0_[28].key_expansion_unit/round_keys_out_reg_n_0_[28]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth20
r10_invsubbytes/D[34]r10_invsubbytes/D[34]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2�
Gr10_invsubbytes/p_0_out_inferred__3/r10_invsubbytes_reg_reg[34]_i_2_n_0Gr10_invsubbytes/p_0_out_inferred__3/r10_invsubbytes_reg_reg[34]_i_2_n_08Z32-702h px� 
_
!Optimized %s %s.  Swapped %s %s.
322*physynth2
12
net2
242
pinsZ32-608h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2h
1key_expansion_unit/r9_invmixcolumns_reg[5]_i_1_101key_expansion_unit/r9_invmixcolumns_reg[5]_i_1_108Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.2192
-135951.763Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth20
r10_invsubbytes/D[93]r10_invsubbytes/D[93]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2�
Hr10_invsubbytes/p_0_out_inferred__10/r10_invsubbytes_reg_reg[93]_i_2_n_0Hr10_invsubbytes/p_0_out_inferred__10/r10_invsubbytes_reg_reg[93]_i_2_n_08Z32-702h px� 
_
!Optimized %s %s.  Swapped %s %s.
322*physynth2
12
net2
242
pinsZ32-608h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2j
2key_expansion_unit/r9_invmixcolumns_reg[93]_i_1_132key_expansion_unit/r9_invmixcolumns_reg[93]_i_1_138Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.2162
-135951.705Z32-619h px� 
�
(Processed net %s.  Re-placed instance %s337*physynth24
r10_invsubbytes_reg[22]r10_invsubbytes_reg[22]2<
r10_invsubbytes_reg_reg[22]	r10_invsubbytes_reg_reg[22]8Z32-663h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth24
r10_invsubbytes_reg[22]r10_invsubbytes_reg[22]8Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.2152
-135951.457Z32-619h px� 
�
(Processed net %s.  Re-placed instance %s337*physynth24
r10_invsubbytes_reg[78]r10_invsubbytes_reg[78]2<
r10_invsubbytes_reg_reg[78]	r10_invsubbytes_reg_reg[78]8Z32-663h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth24
r10_invsubbytes_reg[78]r10_invsubbytes_reg[78]8Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.2152
-135951.210Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth24
r10_addroundkey_reg[66]r10_addroundkey_reg[66]8Z32-702h px� 
�
(Processed net %s.  Re-placed instance %s337*physynth2
key_buf[122]key_buf[122]2&
key_buf_reg[122]	key_buf_reg[122]8Z32-663h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2
key_buf[122]key_buf[122]8Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.2132
-135919.137Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2@
r10_invaddroundkey_reg__0[34]r10_invaddroundkey_reg__0[34]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2b
.key_expansion_unit/round_keys_out_reg_n_0_[28].key_expansion_unit/round_keys_out_reg_n_0_[28]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth20
r10_invsubbytes/D[34]r10_invsubbytes/D[34]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2�
Gr10_invsubbytes/p_0_out_inferred__3/r10_invsubbytes_reg_reg[34]_i_2_n_0Gr10_invsubbytes/p_0_out_inferred__3/r10_invsubbytes_reg_reg[34]_i_2_n_08Z32-702h px� 
_
!Optimized %s %s.  Swapped %s %s.
322*physynth2
12
net2
242
pinsZ32-608h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2f
0key_expansion_unit/r9_invmixcolumns_reg[5]_i_1_20key_expansion_unit/r9_invmixcolumns_reg[5]_i_1_28Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.2102
-135919.094Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2:
r10_invaddroundkey_reg[23]r10_invaddroundkey_reg[23]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2b
.key_expansion_unit/round_keys_out_reg_n_0_[41].key_expansion_unit/round_keys_out_reg_n_0_[41]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth20
r10_invsubbytes/D[23]r10_invsubbytes/D[23]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2�
Gr10_invsubbytes/p_0_out_inferred__1/r10_invsubbytes_reg_reg[23]_i_2_n_0Gr10_invsubbytes/p_0_out_inferred__1/r10_invsubbytes_reg_reg[23]_i_2_n_08Z32-702h px� 
_
!Optimized %s %s.  Swapped %s %s.
322*physynth2
12
net2
242
pinsZ32-608h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2j
2key_expansion_unit/r9_invmixcolumns_reg[53]_i_1_152key_expansion_unit/r9_invmixcolumns_reg[53]_i_1_158Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.2072
-135918.846Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2:
r10_invaddroundkey_reg[47]r10_invaddroundkey_reg[47]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth20
r10_invsubbytes/D[47]r10_invsubbytes/D[47]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2�
Gr10_invsubbytes/p_0_out_inferred__4/r10_invsubbytes_reg_reg[47]_i_2_n_0Gr10_invsubbytes/p_0_out_inferred__4/r10_invsubbytes_reg_reg[47]_i_2_n_08Z32-702h px� 
_
!Optimized %s %s.  Swapped %s %s.
322*physynth2
12
net2
242
pinsZ32-608h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2j
2key_expansion_unit/r9_invmixcolumns_reg[109]_i_1_72key_expansion_unit/r9_invmixcolumns_reg[109]_i_1_78Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.2052
-135918.614Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2<
r10_invaddroundkey_reg[121]r10_invaddroundkey_reg[121]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth22
r10_invsubbytes/D[121]r10_invsubbytes/D[121]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2�
Ir10_invsubbytes/p_0_out_inferred__14/r10_invsubbytes_reg_reg[121]_i_2_n_0Ir10_invsubbytes/p_0_out_inferred__14/r10_invsubbytes_reg_reg[121]_i_2_n_08Z32-702h px� 
_
!Optimized %s %s.  Swapped %s %s.
322*physynth2
12
net2
242
pinsZ32-608h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2j
2key_expansion_unit/r9_invmixcolumns_reg[125]_i_1_92key_expansion_unit/r9_invmixcolumns_reg[125]_i_1_98Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.2032
-135918.584Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2:
r10_invaddroundkey_reg[17]r10_invaddroundkey_reg[17]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth20
r10_invsubbytes/D[17]r10_invsubbytes/D[17]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2�
Gr10_invsubbytes/p_0_out_inferred__1/r10_invsubbytes_reg_reg[17]_i_2_n_0Gr10_invsubbytes/p_0_out_inferred__1/r10_invsubbytes_reg_reg[17]_i_2_n_08Z32-702h px� 
_
!Optimized %s %s.  Swapped %s %s.
322*physynth2
12
net2
242
pinsZ32-608h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2h
1key_expansion_unit/r9_invmixcolumns_reg[53]_i_1_91key_expansion_unit/r9_invmixcolumns_reg[53]_i_1_98Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.2022
-135918.555Z32-619h px� 
�
(Processed net %s.  Re-placed instance %s337*physynth26
r10_invsubbytes_reg[104]r10_invsubbytes_reg[104]2>
r10_invsubbytes_reg_reg[104]	r10_invsubbytes_reg_reg[104]8Z32-663h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth26
r10_invsubbytes_reg[104]r10_invsubbytes_reg[104]8Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1992
-135917.653Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth28
r10_invaddroundkey_reg[9]r10_invaddroundkey_reg[9]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2
data_buf[0]data_buf[0]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2.
r10_invsubbytes/D[9]r10_invsubbytes/D[9]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2�
Fr10_invsubbytes/p_0_out_inferred__0/r10_invsubbytes_reg_reg[9]_i_3_n_0Fr10_invsubbytes/p_0_out_inferred__0/r10_invsubbytes_reg_reg[9]_i_3_n_08Z32-702h px� 
_
!Optimized %s %s.  Swapped %s %s.
322*physynth2
12
net2
242
pinsZ32-608h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2j
2key_expansion_unit/r9_invmixcolumns_reg[77]_i_1_252key_expansion_unit/r9_invmixcolumns_reg[77]_i_1_258Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1962
-135917.624Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2�
Gr10_invsubbytes/p_0_out_inferred__3/r10_invsubbytes_reg_reg[34]_i_3_n_0Gr10_invsubbytes/p_0_out_inferred__3/r10_invsubbytes_reg_reg[34]_i_3_n_08Z32-702h px� 
_
!Optimized %s %s.  Swapped %s %s.
322*physynth2
12
net2
242
pinsZ32-608h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2h
1key_expansion_unit/r9_invmixcolumns_reg[5]_i_1_181key_expansion_unit/r9_invmixcolumns_reg[5]_i_1_188Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1952
-135917.551Z32-619h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1952
-135917.551Z32-619h px� 
�
I%sTime (s): cpu = %s ; elapsed = %s . Memory (MB): peak = %s ; gain = %s
268*common2
Netlist sorting complete. 2

00:00:002
00:00:00.1052

3317.5122
0.000Z17-268h px� 
T
%s*common2;
9Phase 3 Critical Path Optimization | Checksum: 19448f8a9
h px� 
}

%s
*constraints2]
[Time (s): cpu = 00:00:09 ; elapsed = 00:00:05 . Memory (MB): peak = 3317.512 ; gain = 0.000h px� 
W

Phase %s%s
101*constraints2
4 2
Critical Path OptimizationZ18-101h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1952
-135917.551Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2:
r10_invaddroundkey_reg[11]r10_invaddroundkey_reg[11]8Z32-702h px� 
n
'Processed net %s. Replicated %s times.
81*physynth2
data_buf[0]data_buf[0]2
18Z32-81h px� 

;Processed net %s. Optimization improves timing on the net.
394*physynth2
data_buf[0]data_buf[0]8Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1942
-135914.961Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth24
r10_addroundkey_reg[66]r10_addroundkey_reg[66]8Z32-702h px� 
�
(Processed net %s.  Re-placed instance %s337*physynth2 
data_buf[120]data_buf[120]2(
data_buf_reg[120]	data_buf_reg[120]8Z32-663h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2 
data_buf[120]data_buf[120]8Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1932
-135895.199Z32-619h px� 
�
(Processed net %s.  Re-placed instance %s337*physynth24
r10_invsubbytes_reg[24]r10_invsubbytes_reg[24]2<
r10_invsubbytes_reg_reg[24]	r10_invsubbytes_reg_reg[24]8Z32-663h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth24
r10_invsubbytes_reg[24]r10_invsubbytes_reg[24]8Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1912
-135894.297Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2<
r10_invaddroundkey_reg[121]r10_invaddroundkey_reg[121]8Z32-702h px� 
�
'Processed net %s. Replicated %s times.
81*physynth2b
.key_expansion_unit/round_keys_out_reg_n_0_[41].key_expansion_unit/round_keys_out_reg_n_0_[41]2
18Z32-81h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2b
.key_expansion_unit/round_keys_out_reg_n_0_[41].key_expansion_unit/round_keys_out_reg_n_0_[41]8Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1892
-135887.472Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2
data_buf[0]data_buf[0]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth20
r10_invsubbytes/D[11]r10_invsubbytes/D[11]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2�
Gr10_invsubbytes/p_0_out_inferred__0/r10_invsubbytes_reg_reg[11]_i_2_n_0Gr10_invsubbytes/p_0_out_inferred__0/r10_invsubbytes_reg_reg[11]_i_2_n_08Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2h
1key_expansion_unit/r9_invmixcolumns_reg[77]_i_1_31key_expansion_unit/r9_invmixcolumns_reg[77]_i_1_38Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2\
+key_expansion_unit/r9_invmixcolumns_out[75]+key_expansion_unit/r9_invmixcolumns_out[75]8Z32-702h px� 
�
(Processed net %s.  Re-placed instance %s337*physynth2l
3key_expansion_unit/r9_invmixcolumns_reg[68]_i_3_n_03key_expansion_unit/r9_invmixcolumns_reg[68]_i_3_n_02d
/key_expansion_unit/r9_invmixcolumns_reg[68]_i_3	/key_expansion_unit/r9_invmixcolumns_reg[68]_i_38Z32-663h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2l
3key_expansion_unit/r9_invmixcolumns_reg[68]_i_3_n_03key_expansion_unit/r9_invmixcolumns_reg[68]_i_3_n_08Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1852
-135891.154Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2
data_buf[88]data_buf[88]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth22
r10_invsubbytes/D[121]r10_invsubbytes/D[121]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2�
Ir10_invsubbytes/p_0_out_inferred__14/r10_invsubbytes_reg_reg[121]_i_2_n_0Ir10_invsubbytes/p_0_out_inferred__14/r10_invsubbytes_reg_reg[121]_i_2_n_08Z32-702h px� 
_
!Optimized %s %s.  Swapped %s %s.
322*physynth2
12
net2
242
pinsZ32-608h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2j
2key_expansion_unit/r9_invmixcolumns_reg[125]_i_1_12key_expansion_unit/r9_invmixcolumns_reg[125]_i_1_18Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1842
-135891.140Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2:
r10_invaddroundkey_reg[17]r10_invaddroundkey_reg[17]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2d
/key_expansion_unit/round_keys_out_reg_n_0_[104]/key_expansion_unit/round_keys_out_reg_n_0_[104]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth20
r10_invsubbytes/D[17]r10_invsubbytes/D[17]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2�
Gr10_invsubbytes/p_0_out_inferred__1/r10_invsubbytes_reg_reg[17]_i_2_n_0Gr10_invsubbytes/p_0_out_inferred__1/r10_invsubbytes_reg_reg[17]_i_2_n_08Z32-702h px� 
_
!Optimized %s %s.  Swapped %s %s.
322*physynth2
12
net2
242
pinsZ32-608h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2h
1key_expansion_unit/r9_invmixcolumns_reg[53]_i_1_11key_expansion_unit/r9_invmixcolumns_reg[53]_i_1_18Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1842
-135890.979Z32-619h px� 
�
(Processed net %s.  Re-placed instance %s337*physynth24
r10_invsubbytes_reg[90]r10_invsubbytes_reg[90]2<
r10_invsubbytes_reg_reg[90]	r10_invsubbytes_reg_reg[90]8Z32-663h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth24
r10_invsubbytes_reg[90]r10_invsubbytes_reg[90]8Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1832
-135890.092Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2:
r10_invaddroundkey_reg[93]r10_invaddroundkey_reg[93]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth20
r10_invsubbytes/D[93]r10_invsubbytes/D[93]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2�
Hr10_invsubbytes/p_0_out_inferred__10/r10_invsubbytes_reg_reg[93]_i_2_n_0Hr10_invsubbytes/p_0_out_inferred__10/r10_invsubbytes_reg_reg[93]_i_2_n_08Z32-702h px� 
_
!Optimized %s %s.  Swapped %s %s.
322*physynth2
12
net2
242
pinsZ32-608h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2j
2key_expansion_unit/r9_invmixcolumns_reg[93]_i_1_132key_expansion_unit/r9_invmixcolumns_reg[93]_i_1_138Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1812
-135890.077Z32-619h px� 
�
(Processed net %s.  Re-placed instance %s337*physynth26
r10_invsubbytes_reg[105]r10_invsubbytes_reg[105]2>
r10_invsubbytes_reg_reg[105]	r10_invsubbytes_reg_reg[105]8Z32-663h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth26
r10_invsubbytes_reg[105]r10_invsubbytes_reg[105]8Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1812
-135889.190Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2:
r10_invaddroundkey_reg[93]r10_invaddroundkey_reg[93]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2b
.key_expansion_unit/round_keys_out_reg_n_0_[28].key_expansion_unit/round_keys_out_reg_n_0_[28]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth20
r10_invsubbytes/D[93]r10_invsubbytes/D[93]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2�
Hr10_invsubbytes/p_0_out_inferred__10/r10_invsubbytes_reg_reg[93]_i_3_n_0Hr10_invsubbytes/p_0_out_inferred__10/r10_invsubbytes_reg_reg[93]_i_3_n_08Z32-702h px� 
_
!Optimized %s %s.  Swapped %s %s.
322*physynth2
12
net2
242
pinsZ32-608h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2j
2key_expansion_unit/r9_invmixcolumns_reg[93]_i_1_292key_expansion_unit/r9_invmixcolumns_reg[93]_i_1_298Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1802
-135889.175Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth24
r10_addroundkey_reg[66]r10_addroundkey_reg[66]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2
key_buf[120]key_buf[120]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2J
"r10_subbytes/r10_subbytes_wire[98]"r10_subbytes/r10_subbytes_wire[98]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2�
Cr10_subbytes/p_0_out_inferred__11/r10_shiftrows_reg_reg[66]_i_3_n_0Cr10_subbytes/p_0_out_inferred__11/r10_shiftrows_reg_reg[66]_i_3_n_08Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2R
&r1_subbytes/round_keys_out_reg[224]_25&r1_subbytes/round_keys_out_reg[224]_258Z32-702h px� 
_
!Optimized %s %s.  Swapped %s %s.
322*physynth2
12
net2
162
pinsZ32-608h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2Z
*key_expansion_unit/r9_addroundkey_wire[38]*key_expansion_unit/r9_addroundkey_wire[38]8Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1792
-135884.577Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2:
r10_invaddroundkey_reg[11]r10_invaddroundkey_reg[11]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2
data_buf[0]data_buf[0]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth20
r10_invsubbytes/D[11]r10_invsubbytes/D[11]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2�
Gr10_invsubbytes/p_0_out_inferred__0/r10_invsubbytes_reg_reg[11]_i_3_n_0Gr10_invsubbytes/p_0_out_inferred__0/r10_invsubbytes_reg_reg[11]_i_3_n_08Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2j
2key_expansion_unit/r9_invmixcolumns_reg[77]_i_1_272key_expansion_unit/r9_invmixcolumns_reg[77]_i_1_278Z32-702h px� 
_
!Optimized %s %s.  Swapped %s %s.
322*physynth2
12
net2
242
pinsZ32-608h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2\
+key_expansion_unit/r9_invmixcolumns_out[72]+key_expansion_unit/r9_invmixcolumns_out[72]8Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1792
-135883.733Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2<
r10_invaddroundkey_reg[121]r10_invaddroundkey_reg[121]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2
data_buf[88]data_buf[88]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth22
r10_invsubbytes/D[121]r10_invsubbytes/D[121]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2�
Ir10_invsubbytes/p_0_out_inferred__14/r10_invsubbytes_reg_reg[121]_i_3_n_0Ir10_invsubbytes/p_0_out_inferred__14/r10_invsubbytes_reg_reg[121]_i_3_n_08Z32-702h px� 
_
!Optimized %s %s.  Swapped %s %s.
322*physynth2
12
net2
242
pinsZ32-608h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2l
3key_expansion_unit/r9_invmixcolumns_reg[125]_i_1_253key_expansion_unit/r9_invmixcolumns_reg[125]_i_1_258Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1752
-135883.703Z32-619h px� 
_
!Optimized %s %s.  Swapped %s %s.
322*physynth2
12
net2
242
pinsZ32-608h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2j
2key_expansion_unit/r9_invmixcolumns_reg[93]_i_1_212key_expansion_unit/r9_invmixcolumns_reg[93]_i_1_218Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1722
-135883.689Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2<
r10_invaddroundkey_reg[120]r10_invaddroundkey_reg[120]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth22
r10_invsubbytes/D[120]r10_invsubbytes/D[120]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2�
Ir10_invsubbytes/p_0_out_inferred__14/r10_invsubbytes_reg_reg[120]_i_2_n_0Ir10_invsubbytes/p_0_out_inferred__14/r10_invsubbytes_reg_reg[120]_i_2_n_08Z32-702h px� 
_
!Optimized %s %s.  Swapped %s %s.
322*physynth2
12
net2
242
pinsZ32-608h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2j
2key_expansion_unit/r9_invmixcolumns_reg[125]_i_1_82key_expansion_unit/r9_invmixcolumns_reg[125]_i_1_88Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1712
-135883.660Z32-619h px� 
�
(Processed net %s.  Re-placed instance %s337*physynth24
r10_invsubbytes_reg[88]r10_invsubbytes_reg[88]2<
r10_invsubbytes_reg_reg[88]	r10_invsubbytes_reg_reg[88]8Z32-663h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth24
r10_invsubbytes_reg[88]r10_invsubbytes_reg[88]8Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1702
-135882.758Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2�
Gr10_invsubbytes/p_0_out_inferred__0/r10_invsubbytes_reg_reg[11]_i_2_n_0Gr10_invsubbytes/p_0_out_inferred__0/r10_invsubbytes_reg_reg[11]_i_2_n_08Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2h
1key_expansion_unit/r9_invmixcolumns_reg[77]_i_1_31key_expansion_unit/r9_invmixcolumns_reg[77]_i_1_38Z32-702h px� 
�
(Processed net %s.  Re-placed instance %s337*physynth2\
+key_expansion_unit/r9_invmixcolumns_out[75]+key_expansion_unit/r9_invmixcolumns_out[75]2d
/key_expansion_unit/r9_invmixcolumns_reg[75]_i_1	/key_expansion_unit/r9_invmixcolumns_reg[75]_i_18Z32-663h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2\
+key_expansion_unit/r9_invmixcolumns_out[75]+key_expansion_unit/r9_invmixcolumns_out[75]8Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1702
-135882.525Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth28
r10_invaddroundkey_reg[9]r10_invaddroundkey_reg[9]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2.
r10_invsubbytes/D[9]r10_invsubbytes/D[9]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2�
Fr10_invsubbytes/p_0_out_inferred__0/r10_invsubbytes_reg_reg[9]_i_3_n_0Fr10_invsubbytes/p_0_out_inferred__0/r10_invsubbytes_reg_reg[9]_i_3_n_08Z32-702h px� 
_
!Optimized %s %s.  Swapped %s %s.
322*physynth2
12
net2
242
pinsZ32-608h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2j
2key_expansion_unit/r9_invmixcolumns_reg[77]_i_1_252key_expansion_unit/r9_invmixcolumns_reg[77]_i_1_258Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1672
-135882.263Z32-619h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2:
r10_invaddroundkey_reg[79]r10_invaddroundkey_reg[79]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2d
/key_expansion_unit/round_keys_out_reg_n_0_[104]/key_expansion_unit/round_keys_out_reg_n_0_[104]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth20
r10_invsubbytes/D[79]r10_invsubbytes/D[79]8Z32-702h px� 
�
BPorcessed net %s. Optimizations did not improve timing on the net.366*physynth2�
Gr10_invsubbytes/p_0_out_inferred__8/r10_invsubbytes_reg_reg[79]_i_2_n_0Gr10_invsubbytes/p_0_out_inferred__8/r10_invsubbytes_reg_reg[79]_i_2_n_08Z32-702h px� 
_
!Optimized %s %s.  Swapped %s %s.
322*physynth2
12
net2
242
pinsZ32-608h px� 
�
;Processed net %s. Optimization improves timing on the net.
394*physynth2j
2key_expansion_unit/r9_invmixcolumns_reg[13]_i_1_152key_expansion_unit/r9_invmixcolumns_reg[13]_i_1_158Z32-735h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1672
-135882.248Z32-619h px� 
w
(%s %s Timing Summary | WNS=%s | TNS=%s |333*physynth2
	Estimated2
 2	
-39.1672
-135882.248Z32-619h px� 
�
I%sTime (s): cpu = %s ; elapsed = %s . Memory (MB): peak = %s ; gain = %s
268*common2
Netlist sorting complete. 2

00:00:002
00:00:00.1832

3317.5122
0.000Z17-268h px� 
S
%s*common2:
8Phase 4 Critical Path Optimization | Checksum: d719163d
h px� 
}

%s
*constraints2]
[Time (s): cpu = 00:00:21 ; elapsed = 00:00:12 . Memory (MB): peak = 3317.512 ; gain = 0.000h px� 
�
I%sTime (s): cpu = %s ; elapsed = %s . Memory (MB): peak = %s ; gain = %s
268*common2
Netlist sorting complete. 2

00:00:002
00:00:00.0042

3317.5122
0.000Z17-268h px� 
|
>Post Physical Optimization Timing Summary | WNS=%s | TNS=%s |
318*physynth2	
-39.1672
-135882.248Z32-603h px� 
B
-
Summary of Physical Synthesis Optimizations
*commonh px� 
B
-============================================
*commonh px� 


*commonh px� 


*commonh px� 
�
�-------------------------------------------------------------------------------------------------------------------------------------------------------------
*commonh px� 
�
�|  Optimization   |  WNS Gain (ns)  |  TNS Gain (ns)  |  Added Cells  |  Removed Cells  |  Optimized Cells/Nets  |  Dont Touch  |  Iterations  |  Elapsed   |
-------------------------------------------------------------------------------------------------------------------------------------------------------------
*commonh px� 
�
�|  DSP Register   |          0.000  |          0.000  |            0  |              0  |                     0  |           0  |           1  |  00:00:00  |
|  Critical Path  |          0.061  |         97.323  |            3  |              0  |                    40  |           0  |           2  |  00:00:10  |
|  Total          |          0.061  |         97.323  |            3  |              0  |                    40  |           0  |           3  |  00:00:10  |
-------------------------------------------------------------------------------------------------------------------------------------------------------------
*commonh px� 


*commonh px� 


*commonh px� 
�
I%sTime (s): cpu = %s ; elapsed = %s . Memory (MB): peak = %s ; gain = %s
268*common2
Netlist sorting complete. 2

00:00:002
00:00:00.0052

3317.5122
0.000Z17-268h px� 
P
%s*common27
5Ending Physical Synthesis Task | Checksum: 27187e61e
h px� 
}

%s
*constraints2]
[Time (s): cpu = 00:00:21 ; elapsed = 00:00:12 . Memory (MB): peak = 3317.512 ; gain = 0.000h px� 
H
Releasing license: %s
83*common2
ImplementationZ17-83h px� 

G%s Infos, %s Warnings, %s Critical Warnings and %s Errors encountered.
28*	vivadotcl2
2912
02
02
0Z4-41h px� 
O
%s completed successfully
29*	vivadotcl2
phys_opt_designZ4-42h px� 
�
I%sTime (s): cpu = %s ; elapsed = %s . Memory (MB): peak = %s ; gain = %s
268*common2
phys_opt_design: 2

00:00:272

00:00:162

3317.5122
11.559Z17-268h px� 
H
&Writing timing data to binary archive.266*timingZ38-480h px� 
�
I%sTime (s): cpu = %s ; elapsed = %s . Memory (MB): peak = %s ; gain = %s
268*common2
Write ShapeDB Complete: 2

00:00:022
00:00:00.2642

3317.5122
0.000Z17-268h px� 
�
I%sTime (s): cpu = %s ; elapsed = %s . Memory (MB): peak = %s ; gain = %s
268*common2
Wrote PlaceDB: 2

00:00:042

00:00:012

3317.5122
0.000Z17-268h px� 
�
I%sTime (s): cpu = %s ; elapsed = %s . Memory (MB): peak = %s ; gain = %s
268*common2
Wrote PulsedLatchDB: 2

00:00:002

00:00:002

3317.5122
0.000Z17-268h px� 
=
Writing XDEF routing.
211*designutilsZ20-211h px� 
J
#Writing XDEF routing logical nets.
209*designutilsZ20-209h px� 
J
#Writing XDEF routing special nets.
210*designutilsZ20-210h px� 
�
I%sTime (s): cpu = %s ; elapsed = %s . Memory (MB): peak = %s ; gain = %s
268*common2
Wrote RouteStorage: 2

00:00:002
00:00:00.0252

3317.5122
0.000Z17-268h px� 
�
I%sTime (s): cpu = %s ; elapsed = %s . Memory (MB): peak = %s ; gain = %s
268*common2
Wrote Netlist Cache: 2

00:00:002
00:00:00.0422

3317.5122
0.000Z17-268h px� 
�
I%sTime (s): cpu = %s ; elapsed = %s . Memory (MB): peak = %s ; gain = %s
268*common2
Wrote Device Cache: 2

00:00:002
00:00:00.0042

3317.5122
0.000Z17-268h px� 
�
I%sTime (s): cpu = %s ; elapsed = %s . Memory (MB): peak = %s ; gain = %s
268*common2
Write Physdb Complete: 2

00:00:042

00:00:012

3317.5122
0.000Z17-268h px� 
�
 The %s '%s' has been generated.
621*common2

checkpoint2_
]D:/Licenta/Licenta/PROIECT LICENTA  FINAL/project_1/project_1.runs/impl_1/AES_TOP_physopt.dcpZ17-1381h px� 


End Record