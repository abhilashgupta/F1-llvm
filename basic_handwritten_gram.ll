; -> the semi-colon is the character to start a one-line comment
; This is the implementation of the F1 fuzzer for the grammar '"<start>" : [["a"]]'.
; -> @max_depth is defined as a global 32-bit integer, aligned to 4 bytes
@max_depth = global i32 10, align 4
; @.start.0 is the "a" in '"<start>" : [["a"]]'
; @.newline is the '\n' printed out at the end of gen_init.
@.start.0 = private unnamed_addr constant [2 x i8] c"a\00", align 1
@.newline = private unnamed_addr constant [2 x i8] c"\0A\00", align 1

; @map is a function that returns a random integer in a range [0, %val)
define i32 @map(i32 %val) {
    %random_int = call i32 @rand() ; @rand() is cstdlib's rand() function
    %random_choice = srem i32 %random_int, %val ; random_int % val
    ret i32 %random_choice; return random_choice
}
declare i32 @rand() ; declare cstdlib's rand

;@gen_start procedure
define void @gen_start(i32 %depth) {
    ; load the value of max_depth into %max_depth_var
    %max_depth_var = load i32, i32* @max_depth, align 4
    %comparision_result1 = icmp sgt i32 %depth, %max_depth_var ; bool comparision_result1 = depth > max_depth
    ; branch jump to s_expr if comparision_result1 == true, else, jump to full_expansion
    br i1 %comparision_result1, label %s_expr, label %full_expansion
  s_expr:
    %random_choice = call i32 @map(i32 1) ; random_choice = map(1)
    ; switch based on random_choice's value, default is return_block
    ; the switch cases are separated by newline
    switch i32 %random_choice, label %return_block [
        i32 0, label %case0 ; jump to case0, if random_choice = 0
    ]
    br label %return_block ; branch jump to return_block
  case0:
    ; printf(@.start.0)
    %printf_call1 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([2 x i8], [2 x i8]* @.start.0, i64 0, i64 0))
    br label %return_block
  full_expansion:
    %random_choice1 = call i32 @map(i32 1) ; random_choice1 = map(1)
    ; switch based on random_choice1's value, default is return_block
    switch i32 %random_choice1, label %return_block [
        i32 0, label %case0 ; jump to case0, when random_choice1 is 0
    ]
  return_block:
    ret void ; return void
}
declare i32 @printf(i8*, ...) ; declare cstdio's printf

; gen_init__ procedure
define void @gen_init__(){
  call void @gen_start(i32 0) ; calling gen_start(depth=0)
  ; printf(@.newline)
  call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([2 x i8], [2 x i8]* @.newline, i64 0, i64 0))
  ret void ; return void
}

define i32 @main(){
    %i_pointer = alloca i32, align 4 ; loop variable pointer on stack
    store i32 0, i32* %i_pointer, align 4 ;write i = 0 to memory
    %seed_location = alloca i32, align 4 ; pointer to seed on stack
    store i32 0, i32* %seed_location, align 4 ; write seed = 0 to memory
    %seed = load i32, i32* %seed_location, align 4 ; load seed's value into a variable
    call void @srand(i32 %seed) ; invoke stdlib's srand  with seed
    ; an alternative to previous 4 lines is to invoke srand directly with 10, if seed is fixed
    %max_loop_p = alloca i32, align 4 ; maximum possible value of loop variable pointer on stack
    store i32 10, i32* %max_loop_p, align 4 ; write max_loop = 10 to memory
    br label %comparision_check; branch jump to comparision_check

  comparision_check:
    ; load the value of i_pointer into variable i
    %i = load i32, i32* %i_pointer, align 4
    ; load the value of max_loop_p into variable max_num (an alternative is compare directly to 10, if max_num is fixed)
    %max_num = load i32, i32* %max_loop_p, align 4
    %comparision_result1 = icmp slt i32 %i, %max_num ; comparision_result1 = true if i < max_num, false otherwise
    ;branch jump to call_gen_init__ if comparision_result1 is true, jump to return_block otherwise
    br i1 %comparision_result1, label %call_gen_init__, label %return_block

  call_gen_init__:
    call void @gen_init__() ; invoke gen_init__()
    %i_new = add nsw i32 %i, 1 ; update i(new) = i + 1
    store i32 %i_new, i32* %i_pointer, align 4; write updated i to memory
    br label %comparision_check

  return_block:
    ret i32 0
}
declare void @srand(i32)