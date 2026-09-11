; JOCKY Forensic Polymorphic LLVM IR
target triple = "x86_64-unknown-linux-gnu"

; Runtime Declarations
declare i32 @jocky_init_session(i8* %target, i8* %warrant)
declare i32 @jocky_collect_artifact(i32 %type, i8* %expr)
declare i32 @jocky_encrypt_payload(i32 %algo, i8* %key_source)
declare i32 @jocky_transmit_secure(i8* %endpoint)

; Constant String Literals
@.str.0 = private unnamed_addr constant [10 x i8] c"10.0.5.42\00", align 1
@.str.1 = private unnamed_addr constant [21 x i8] c"NTRO-2026-LINUX-0089\00", align 1
@.str.2 = private unnamed_addr constant [14 x i8] c"all_processes\00", align 1
@.str.3 = private unnamed_addr constant [10 x i8] c"pipe_expr\00", align 1
@.str.4 = private unnamed_addr constant [19 x i8] c"active_connections\00", align 1
@.str.5 = private unnamed_addr constant [12 x i8] c"hsm_derived\00", align 1
@.str.6 = private unnamed_addr constant [39 x i8] c"wss://cloudfront.ntro.gov.in/forensics\00", align 1

; Session: target=10.0.5.42 warrant=NTRO-2026-LINUX-0089
define i32 @forensic_session_0() {
entry:
  %target_ptr = getelementptr inbounds [10 x i8], [10 x i8]* @.str.0, i64 0, i64 0
  %warrant_ptr = getelementptr inbounds [21 x i8], [21 x i8]* @.str.1, i64 0, i64 0
  %init_res = call i32 @jocky_init_session(i8* %target_ptr, i8* %warrant_ptr)
  ; collect /proc artifact
  %expr_ptr_3 = getelementptr inbounds [14 x i8], [14 x i8]* @.str.2, i64 0, i64 0
  call i32 @jocky_collect_artifact(i32 5, i8* %expr_ptr_3)
  ; collect auditd artifact
  %expr_ptr_4 = getelementptr inbounds [10 x i8], [10 x i8]* @.str.3, i64 0, i64 0
  call i32 @jocky_collect_artifact(i32 6, i8* %expr_ptr_4)
  ; collect network artifact
  %expr_ptr_5 = getelementptr inbounds [19 x i8], [19 x i8]* @.str.4, i64 0, i64 0
  call i32 @jocky_collect_artifact(i32 3, i8* %expr_ptr_5)
  ; encrypt with ml_kem key=hsm_derived
  %key_ptr_6 = getelementptr inbounds [12 x i8], [12 x i8]* @.str.5, i64 0, i64 0
  call i32 @jocky_encrypt_payload(i32 3, i8* %key_ptr_6)
  ; transmit to wss://cloudfront.ntro.gov.in/forensics
  %ep_ptr_7 = getelementptr inbounds [39 x i8], [39 x i8]* @.str.6, i64 0, i64 0
  call i32 @jocky_transmit_secure(i8* %ep_ptr_7)
  ret i32 0
}

; end of module