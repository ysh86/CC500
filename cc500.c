/*
 * Copyright (C) 2006 Edmund GRIMLEY EVANS <edmundo@rano.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * A self-compiling compiler for a small subset of C.
 */

/* Our library functions. */
void exit(int);
int getchar(void);
void *malloc(int);
int putchar(int);

/* The first thing defined must be main(). */
int main1();
int main()
{
  return main1();
}

char *my_realloc(char *old, int oldlen, int newlen)
{
  char *new = malloc(newlen);
  int i = 0;
  while (i <= oldlen - 1) {
    new[i] = old[i];
    i = i + 1;
  }
  return new;
}

int nextc;
char *token;
int token_size;

void error()
{
  exit(1);
}

int i;

void takechar()
{
  if (token_size <= i + 1) {
    int x = (i + 10) << 1;
    token = my_realloc(token, token_size, x);
    token_size = x;
  }
  token[i] = nextc;
  i = i + 1;
  nextc = getchar();
}

void get_token()
{
  int w = 1;
  while (w) {
    w = 0;
    while ((nextc == ' ') | (nextc == 9) | (nextc == 10)) /* ASCII 9 = TAB, ASCII 10 = LF*/
      nextc = getchar();
    i = 0;
    while ((('a' <= nextc) & (nextc <= 'z')) |
           (('0' <= nextc) & (nextc <= '9')) | (nextc == '_'))
      takechar();
    if (i == 0)
      while ((nextc == '<') | (nextc == '=') | (nextc == '>') |
             (nextc == '|') | (nextc == '&') | (nextc == '!'))
        takechar();
    if (i == 0) {
      if (nextc == 39) { /* ASCII 39 = ' */
        takechar();
        while (nextc != 39)
          takechar();
        takechar();
      }
      else if (nextc == '"') {
        takechar();
        while (nextc != '"')
          takechar();
        takechar();
      }
      else if (nextc == '/') {
        takechar();
        if (nextc == '*') {
          nextc = getchar();
          while (nextc != '/') {
            while (nextc != '*')
              nextc = getchar();
            nextc = getchar();
          }
          nextc = getchar();
          w = 1;
        }
      }
      else if (nextc != 0-1)
        takechar();
    }
    token[i] = 0;
  }
}

int peek(char *s)
{
  int i = 0;
  while ((s[i] == token[i]) & (s[i] != 0))
    i = i + 1;
  return s[i] == token[i];
}

int accept(char *s)
{
  if (peek(s)) {
    get_token();
    return 1;
  }
  else
    return 0;
}

void expect(char *s)
{
  if (accept(s) == 0)
    error();
}

char *code;
int code_size;
int codepos;
int code_offset;

void save_int(char *p, int n)
{
  p[0] = n;
  p[1] = n >> 8;
  p[2] = n >> 16;
  p[3] = n >> 24;
}

void save_char(char *p, int n)
{
  p[0] = n;
}

int load_int(char *p)
{
  return ((p[0] & 255) + ((p[1] & 255) << 8) +
          ((p[2] & 255) << 16) + ((p[3] & 255) << 24));
}

void emit(int n, char *s)
{
  i = 0;
  if (code_size <= codepos + n) {
    int x = (codepos + n) << 1;
    code = my_realloc(code, code_size, x);
    code_size = x;
  }
  while (i <= n - 1) {
    code[codepos] = s[i];
    codepos = codepos + 1;
    i = i + 1;
  }
}

void be_set_int_to_reg0(int n)
{
  emit(4, "\x00\x00\xa0\xe3"); /* mov r0, #n */
  save_char(code + codepos - 4, n);
  n = n >> 8;
  if (n) {
    emit(4, "\x00\x20\xa0\xe3"); /* mov r2, #n */
    save_char(code + codepos - 4, n);
    emit(4, "\x02\x04\x80\xe0"); /* add r0, r0, r2, LSL #8 */
  }
  n = n >> 8;
  if (n) {
    emit(4, "\x00\x20\xa0\xe3"); /* mov r2, #n */
    save_char(code + codepos - 4, n);
    emit(4, "\x02\x08\x80\xe0"); /* add r0, r0, r2, LSL #16 */
  }
  n = n >> 8;
  if (n) {
    emit(4, "\x00\x20\xa0\xe3"); /* mov r2, #n */
    save_char(code + codepos - 4, n);
    emit(4, "\x02\x0c\x80\xe0"); /* add r0, r0, r2, LSL #24 */
  }
}

void be_set_int_to_reg1(int n)
{
  emit(4, "\x00\x10\xa0\xe3"); /* mov r1, #n */
  save_char(code + codepos - 4, n);
  n = n >> 8;
  if (n) {
    emit(4, "\x00\x20\xa0\xe3"); /* mov r2, #n */
    save_char(code + codepos - 4, n);
    emit(4, "\x02\x14\x81\xe0"); /* add r1, r1, r2, LSL #8 */
  }
  n = n >> 8;
  if (n) {
    emit(4, "\x00\x20\xa0\xe3"); /* mov r2, #n */
    save_char(code + codepos - 4, n);
    emit(4, "\x02\x18\x81\xe0"); /* add r1, r1, r2, LSL #16 */
  }
  n = n >> 8;
  if (n) {
    emit(4, "\x00\x20\xa0\xe3"); /* mov r2, #n */
    save_char(code + codepos - 4, n);
    emit(4, "\x02\x1c\x81\xe0"); /* add r1, r1, r2, LSL #24 */
  }
}

void be_push()
{
  emit(4, "\x01\x00\x2d\xe9"); /* push %eax */ /* stmfd sp!, {r0} */
}

void be_pop(int n)
{
  be_set_int_to_reg1(n << 2);
  emit(4, "\x01\xd0\x8d\xe0"); /* add $(n * 4),%esp */ /* add sp, sp, r1 */
}

char *table;
int table_size;
int table_pos;
int stack_pos;

int sym_lookup(char *s)
{
  int t = 0;
  int current_symbol = 0;
  while (t <= table_pos - 1) {
    i = 0;
    while ((s[i] == table[t]) & (s[i] != 0)) {
      i = i + 1;
      t = t + 1;
    }
    if (s[i] == table[t])
      current_symbol = t;
    while (table[t] != 0)
      t = t + 1;
    t = t + 6;
  }
  return current_symbol;
}

void sym_declare(char *s, int type, int value)
{
  int t = table_pos;
  i = 0;
  while (s[i] != 0) {
    if (table_size <= t + 10) {
      int x = (t + 10) << 1;
      table = my_realloc(table, table_size, x);
      table_size = x;
    }
    table[t] = s[i];
    i = i + 1;
    t = t + 1;
  }
  table[t] = 0;
  table[t + 1] = type;
  save_int(table + t + 2, value);
  table_pos = t + 6;
}

int sym_declare_global(char *s)
{
  int current_symbol = sym_lookup(s);
  if (current_symbol == 0) {
    sym_declare(s, 'U', code_offset);
    current_symbol = table_pos - 6;
  }
  return current_symbol;
}

void sym_define_global(int current_symbol)
{
  int i;
  int j;
  int t = current_symbol;
  int v = codepos + code_offset;
  if (table[t + 1] != 'U')
    error(); /* symbol redefined */
  i = load_int(table + t + 2) - code_offset;
  while (i) {
    j = load_int(code + i) - code_offset;
    save_int(code + i, v);
    i = j;
  }
  table[t + 1] = 'D';
  save_int(table + t + 2, v);
}

int number_of_args;

void sym_get_value(char *s)
{
  int t;
  if ((t = sym_lookup(s)) == 0)
    error();
  emit(4, "\x00\x00\x9f\xe5"); /* ldr r0, [pc] */
  emit(8, "\x00\x00\x00\xea...."); /* b 0 */
  /* emit(5, "\xb8...."); mov $n,%eax */
  save_int(code + codepos - 4, load_int(table + t + 2));
  if (table[t + 1] == 'D') { /* defined global */
  }
  else if (table[t + 1] == 'U') /* undefined global */
    save_int(table + t + 2, codepos + code_offset - 4);
  else if (table[t + 1] == 'L') { /* local variable */
    int k = (stack_pos - table[t + 2] - 1) << 2;
    be_set_int_to_reg1(k);
    emit(4, "\x01\x00\x8d\xe0...."); /* lea (n * 4)(%esp),%eax */ /* add r0, sp, r1 */
  }
  else if (table[t + 1] == 'A') { /* argument */
    int k = (stack_pos + number_of_args - table[t + 2] + 1) << 2; /* +1 means a return addr. */
    be_set_int_to_reg1(k);
    emit(4, "\x01\x00\x8d\xe0...."); /* lea (n * 4)(%esp),%eax */ /* add r0, sp, r1 */
  }
  else
    error();
}

void be_start()
{
  emit(16, "\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  emit(16, "\x02\x00\x28\x00\x01\x00\x00\x00\x54\x80\x00\x00\x34\x00\x00\x00");
  emit(16, "\x00\x00\x00\x00\x00\x00\x00\x05\x34\x00\x20\x00\x01\x00\x28\x00");
  emit(16, "\x04\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00");
  emit(16, "\x00\x80\x00\x00\x60\x00\x00\x00\x60\x00\x00\x00\x07\x00\x00\x00");
  emit( 4, "\x00\x80\x00\x00");
  emit(12,                 "\x00\x00\x00\xeb\x01\x70\xa0\xe3\x00\x00\x00\xef");
  /* x86
  ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Intel 80386
  Version:                           0x1
  Entry point address:               0x8048054
  Start of program headers:          52 (bytes into file)
  Start of section headers:          0 (bytes into file)
  Flags:                             0x0
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         1
  Size of section headers:           0 (bytes)
  Number of section headers:         0
  Section header string table index: 0

  Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  LOAD           0x000000 0x08048000 0x08048000 0x04b10 0x04b10 RWE 0x1000

  401000:       e8 00 00 00 00          call   401005 <___mingw_invalidParameterHandler+0x5>
  401005:       89 c3                   mov    %eax,%ebx
  401007:       31 c0                   xor    %eax,%eax
  401009:       40                      inc    %eax
  40100a:       cd 80                   int    $0x80
  */
  /* ARM
  00000000  7f 45 4c 46 01 01 01 00  00 00 00 00 00 00 00 00
  00000010  02 00 28 00 01 00 00 00  54 80 00 00 34 00 00 00
  00000020  c4 00 00 00 00 00 00 05  34 00 20 00 01 00 28 00
  00000030  06 00 03 00 01 00 00 00  00 00 00 00 00 80 00 00
  00000040  00 80 00 00 7c 00 00 00  7c 00 00 00 05 00 00 00
  00000050  00 80 00 00

  ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           ARM
  Version:                           0x1
  Entry point address:               0x8054
  Start of program headers:          52 (bytes into file)
  Start of section headers:          196 (bytes into file)
  Flags:                             0x5000000, Version5 EABI
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         1
  Size of section headers:           40 (bytes)
  Number of section headers:         6
  Section header string table index: 3

  Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  LOAD           0x000000 0x00008000 0x00008000 0x0007c 0x0007c R E 0x8000
  */

  sym_define_global(sym_declare_global("exit"));
  /*
  ldmfd sp!, {r0}
  mov r7, #1
  swi 0
  */
  emit(4, "\x01\x00\xbd\xe8");
  emit(4, "\x01\x70\xa0\xe3");
  emit(4, "\x00\x00\x00\xef");

  sym_define_global(sym_declare_global("getchar"));
  /*
  mov r0, #0
  stmfd sp!, {r0, lr}
  mov r1, sp
  mov r2, #1
  mov r7, #3
  swi 0
  tst r0, r0
  ldmfd sp!, {r0}
  moveq r0, #0
  subeq r0, r0, #1
  ldmfd sp!, {pc}
  */
  /* mov $3,%eax ; xor %ebx,%ebx ; push %ebx ; mov %esp,%ecx */
  /* xor %edx,%edx ; inc %edx ; int $0x80 */
  /* test %eax,%eax ; pop %eax ; jne . + 7 */
  /* mov $-1,%eax ; ret */
  emit(4, "\x00\x00\xa0\xe3");
  emit(4, "\x01\x40\x2d\xe9");
  emit(4, "\x0d\x10\xa0\xe1");
  emit(4, "\x01\x20\xa0\xe3");
  emit(4, "\x03\x70\xa0\xe3");
  emit(4, "\x00\x00\x00\xef");
  emit(4, "\x00\x00\x10\xe1");
  emit(4, "\x01\x00\xbd\xe8");
  emit(4, "\x00\x00\xa0\x03");
  emit(4, "\x01\x00\x40\x02");
  emit(4, "\x00\x80\xbd\xe8");

  sym_define_global(sym_declare_global("malloc"));
  /*
  stmfd sp!, {lr}
  mov r0, #0
  mov r7, #45
  swi 0
  mov r1, r0 @ r1 = begin
  ldr r2, [sp, #4]
  add r0, r0, r2 @ r0 = end
  stmfd sp!, {r0-r1}
  mov r7, #45
  swi 0
  ldmfd sp!, {r1} @ r1 = end
  cmp r1, r0
  ldmfd sp!, {r0} @ r0 = begin
  movne r0, #0
  subne r0, r0, #1
  ldmfd sp!, {pc}
  */
  /* mov 4(%esp),%eax */
  /* push %eax ; xor %ebx,%ebx ; mov $45,%eax ; int $0x80 */
  /* pop %ebx ; add %eax,%ebx ; push %eax ; push %ebx ; mov $45,%eax */
  /* int $0x80 ; pop %ebx ; cmp %eax,%ebx ; pop %eax ; je . + 7 */
  /* mov $-1,%eax ; ret */
  emit(4, "\x00\x40\x2d\xe9");
  emit(4, "\x00\x00\xa0\xe3");
  emit(4, "\x2d\x70\xa0\xe3");
  emit(4, "\x00\x00\x00\xef");
  emit(4, "\x00\x10\xa0\xe1");
  emit(4, "\x04\x20\x9d\xe5");
  emit(4, "\x02\x00\x80\xe0");
  emit(4, "\x03\x00\x2d\xe9");
  emit(4, "\x2d\x70\xa0\xe3");
  emit(4, "\x00\x00\x00\xef");
  emit(4, "\x02\x00\xbd\xe8");
  emit(4, "\x00\x00\x51\xe1");
  emit(4, "\x01\x00\xbd\xe8");
  emit(4, "\x00\x00\xa0\x13");
  emit(4, "\x01\x00\x40\x12");
  emit(4, "\x00\x80\xbd\xe8");

  sym_define_global(sym_declare_global("putchar"));
  /*
  ldr r0, [sp]
  stmfd sp!, {r0, lr}
  add r1, sp, #8
  mov r0, #1
  mov r2, #1
  mov r7, #4
  swi 0
  ldmfd sp!, {r0, pc}
  */
  /* mov $4,%eax ; xor %ebx,%ebx ; inc %ebx */
  /*  lea 4(%esp),%ecx ; mov %ebx,%edx ; int $0x80 ; ret */
  emit(4, "\x00\x00\x9d\xe5");
  emit(4, "\x01\x40\x2d\xe9");
  emit(4, "\x08\x10\x8d\xe2");
  emit(4, "\x01\x00\xa0\xe3");
  emit(4, "\x01\x20\xa0\xe3");
  emit(4, "\x04\x70\xa0\xe3");
  emit(4, "\x00\x00\x00\xef");
  emit(4, "\x01\x80\xbd\xe8");

  save_int(code + 84, ((codepos - 92)>>2) + 3942645760); /* entry set to first thing in file */ /* 0xeb0000xx */
}

void be_finish()
{
  save_int(code + 32, codepos + 56);
  save_int(code + 68, codepos);
  save_int(code + 72, codepos);

  /* attrib data */
  emit(22, "\x41\x15\x00\x00\x00\x61\x65\x61\x62\x69\x00\x01\x0b\x00\x00\x00\x06\x01\x08\x01\x2c\x01");
  /* symbol table */
  emit( 1, "\x00");
  emit(10, "\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00"); /* .shstrtab */
  emit( 6, "\x2e\x74\x65\x78\x74\x00"); /* .text */
  emit(16, "\x2e\x41\x52\x4d\x2e\x61\x74\x74\x72\x69\x62\x75\x74\x65\x73\x00"); /* .ARM.attributes */
  emit( 1, "\x00");

  /* NULL */
  emit(20, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  emit(20, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  /* .text */
  emit(20, "\x0b\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\x54\x80\x00\x00\x54\x00\x00\x00");
  emit(20, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00");
  save_int(code + codepos - 20, codepos - 80 - 56 - 84);
  /* attrib */
  emit(20, "\x11\x00\x00\x00\x03\x00\x00\x70\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  emit(20, "\x16\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00");
  save_int(code + codepos - 24, codepos - 120 - 56);
  /* symbol */
  emit(20, "\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
  emit(20, "\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00");
  save_int(code + codepos - 24, codepos - 160 - 34);

  i = 0;
  while (i <= codepos - 1) {
    putchar(code[i]);
    i = i + 1;
  }
}

void promote(int type)
{
  /* 1 = char lval, 2 = int lval, 3 = other */
  if (type == 1)
    emit(4, "\x00\x00\xd0\xe5"); /* movsbl (%eax),%eax */ /* ldrb r0, [r0] */
  else if (type == 2)
    emit(4, "\x00\x00\x90\xe5"); /* mov (%eax),%eax */ /* ldr r0, [r0] */
}

int expression();

/*
 * primary-expr:
 *     identifier
 *     constant
 *     ( expression )
 */
int primary_expr()
{
  int type;
  if (('0' <= token[0]) & (token[0] <= '9')) {
    int n = 0;
    i = 0;
    while (token[i]) {
      n = (n << 1) + (n << 3) + token[i] - '0';
      i = i + 1;
    }
    /* emit(5, "\xb8...."); mov $x,%eax */
    be_set_int_to_reg0(n);
    type = 3;
  }
  else if (('a' <= token[0]) & (token[0] <= 'z')) {
    sym_get_value(token);
    type = 2;
  }
  else if (accept("(")) {
    type = expression();
    if (peek(")") == 0)
      error();
  }
  else if ((token[0] == 39) & (token[1] != 0) & /* ASCII 39 = ' */
           (token[2] == 39) & (token[3] == 0)) {
    /* emit(5, "\xb8...."); mov $x,%eax */
    be_set_int_to_reg0(token[1]);
    type = 3;
  }
  else if (token[0] == '"') {
    int i = 0;
    int j = 1;
    int k;
    int l;
    int a;
    while (token[j] != '"') {
      if ((token[j] == 92) & (token[j + 1] == 'x')) { /* ASCII 92 = \ */
        if (token[j + 2] <= '9')
          k = token[j + 2] - '0';
        else
          k = token[j + 2] - 'a' + 10;
        k = k << 4;
        if (token[j + 3] <= '9')
          k = k + token[j + 3] - '0';
        else
          k = k + token[j + 3] - 'a' + 10;
        token[i] = k;
        j = j + 4;
      }
      else {
        token[i] = token[j];
        j = j + 1;
      }
      i = i + 1;
    }
    token[i] = 0;
    l = i + 1;
    a = (l + 3) & 4294967292; /* 0xfffffffc */
    be_set_int_to_reg1(a);
    emit(4, "\x04\x00\x8f\xe2"); /* add r0, pc, #4 */
    emit(8, "\x01\xf0\x8f\xe0...."); /* add pc, pc, r1 */
    save_int(code + codepos - 4, 0);
    emit(l, token); /* the string */
    /* alignment */
    a = a - l;
    if (a == 3) {
      emit(1, token + i);
      emit(1, token + i);
      emit(1, token + i);
    }
    if (a == 2) {
      emit(1, token + i);
      emit(1, token + i);
    }
    if (a == 1) {
      emit(1, token + i);
    }
    type = 3;
  }
  else
    error();
  get_token();
  return type;
}

void binary1(int type)
{
  promote(type);
  be_push();
  stack_pos = stack_pos + 1;
}

int binary2(int type, int n, char *s)
{
  promote(type);
  emit(n, s);
  stack_pos = stack_pos - 1;
  return 3;
}

/*
 * postfix-expr:
 *         primary-expr
 *         postfix-expr [ expression ]
 *         postfix-expr ( expression-list-opt )
 */
int postfix_expr()
{
  int type = primary_expr();
  if (accept("[")) {
    binary1(type); /* pop %ebx ; add %ebx,%eax */ /* ldmfd sp!, {r1} ; add r0, r1, r0 */
    binary2(expression(), 8, "\x02\x00\xbd\xe8\x00\x00\x81\xe0");
    expect("]");
    type = 1;
  }
  else if (accept("(")) {
    int s = stack_pos;
    be_push();
    stack_pos = stack_pos + 1;
    if (accept(")") == 0) {
      promote(expression());
      be_push();
      stack_pos = stack_pos + 1;
      while (accept(",")) {
        promote(expression());
        be_push();
        stack_pos = stack_pos + 1;
      }
      expect(")");
    }
    /* emit(7, "\x8b\x84\x24...."); mov (n * 4)(%esp),%eax */
    be_set_int_to_reg0((stack_pos - s - 1) << 2);
    emit(4, "\x00\x00\x9d\xe7"); /* ldr r0, [sp, r0] */
    emit(4, "\x30\xff\x2f\xe1"); /* call *%eax */ /* blx r0 */
    be_pop(stack_pos - s);
    stack_pos = s;
    type = 3;
  }
  return type;
}

/*
 * additive-expr:
 *         postfix-expr
 *         additive-expr + postfix-expr
 *         additive-expr - postfix-expr
 */
int additive_expr()
{
  int type = postfix_expr();
  while (1) {
    if (accept("+")) {
      binary1(type); /* pop %ebx ; add %ebx,%eax */ /* ldmfd sp!, {r1} ; add r0, r1, r0 */
      type = binary2(postfix_expr(), 8, "\x02\x00\xbd\xe8\x00\x00\x81\xe0");
    }
    else if (accept("-")) {
      binary1(type); /* pop %ebx ; sub %eax,%ebx ; mov %ebx,%eax */ /* ldmfd sp!, {r1} ; sub r0, r1, r0 */
      type = binary2(postfix_expr(), 8, "\x02\x00\xbd\xe8\x00\x00\x41\xe0");
    }
    else
      return type;
  }
}

/*
 * shift-expr:
 *         additive-expr
 *         shift-expr << additive-expr
 *         shift-expr >> additive-expr
 */
int shift_expr()
{
  int type = additive_expr();
  while (1) {
    if (accept("<<")) {
      binary1(type); /* mov %eax,%ecx ; pop %eax ; shl %cl,%eax */ /* ldmfd sp!, {r1} ; mov r0, r1, LSL r0 */
      type = binary2(additive_expr(), 8, "\x02\x00\xbd\xe8\x11\x00\xa0\xe1");
    }
    else if (accept(">>")) {
      binary1(type); /* mov %eax,%ecx ; pop %eax ; sar %cl,%eax */ /* ldmfd sp!, {r1} ; mov r0, r1, ASR r0 */
      type = binary2(additive_expr(), 8, "\x02\x00\xbd\xe8\x51\x00\xa0\xe1");
    }
    else
      return type;
  }
}

/*
 * relational-expr:
 *         shift-expr
 *         relational-expr <= shift-expr
 */
int relational_expr()
{
  int type = shift_expr();
  while (accept("<=")) {
    binary1(type);
    /* pop %ebx ; cmp %eax,%ebx ; setle %al ; movzbl %al,%eax */ /* ldmfd sp!, {r1} ; cmp r1, r0 ; mov r0, #0 ; movle r0, #1 */
    type = binary2(shift_expr(),
                   16, "\x02\x00\xbd\xe8\x00\x00\x51\xe1\x00\x00\xa0\xe3\x01\x00\xa0\xd3");
  }
  return type;
}

/*
 * equality-expr:
 *         relational-expr
 *         equality-expr == relational-expr
 *         equality-expr != relational-expr
 */
int equality_expr()
{
  int type = relational_expr();
  while (1) {
    if (accept("==")) {
      binary1(type);
      /* pop %ebx ; cmp %eax,%ebx ; sete %al ; movzbl %al,%eax */ /* ldmfd sp!, {r1} ; cmp r1, r0 ; mov r0, #0 ; moveq r0, #1 */
      type = binary2(relational_expr(),
                     16, "\x02\x00\xbd\xe8\x00\x00\x51\xe1\x00\x00\xa0\xe3\x01\x00\xa0\x03");
    }
    else if (accept("!=")) {
      binary1(type);
      /* pop %ebx ; cmp %eax,%ebx ; setne %al ; movzbl %al,%eax */ /* ldmfd sp!, {r1} ; cmp r1, r0 ; mov r0, #0 ; movne r0, #1 */
      type = binary2(relational_expr(),
                     16, "\x02\x00\xbd\xe8\x00\x00\x51\xe1\x00\x00\xa0\xe3\x01\x00\xa0\x13");
    }
    else
      return type;
  }
}

/*
 * bitwise-and-expr:
 *         equality-expr
 *         bitwise-and-expr & equality-expr
 */
int bitwise_and_expr()
{
  int type = equality_expr();
  while (accept("&")) {
    binary1(type); /* pop %ebx ; and %ebx,%eax */ /* ldmfd sp!, {r1} ; and r0, r1, r0 */
    type = binary2(equality_expr(), 8, "\x02\x00\xbd\xe8\x00\x00\x01\xe0");
  }
  return type;
}

/*
 * bitwise-or-expr:
 *         bitwise-and-expr
 *         bitwise-and-expr | bitwise-or-expr
 */
int bitwise_or_expr()
{
  int type = bitwise_and_expr();
  while (accept("|")) {
    binary1(type); /* pop %ebx ; or %ebx,%eax */ /* ldmfd sp!, {r1} ; orr r0, r1, r0 */
    type = binary2(bitwise_and_expr(), 8, "\x02\x00\xbd\xe8\x00\x00\x81\xe1");
  }
  return type;
}

/*
 * expression:
 *         bitwise-or-expr
 *         bitwise-or-expr = expression
 */
int expression()
{
  int type = bitwise_or_expr();
  if (accept("=")) {
    be_push();
    stack_pos = stack_pos + 1;
    promote(expression());
    if (type == 2)
      emit(8, "\x02\x00\xbd\xe8\x00\x00\x81\xe5"); /* pop %ebx ; mov %eax,(%ebx) */ /* ldmfd sp!, {r1} ; str r0, [r1] */
    else
      emit(8, "\x02\x00\xbd\xe8\x00\x00\xc1\xe5"); /* pop %ebx ; mov %al,(%ebx) */ /* ldmfd sp!, {r1} ; strb r0, [r1] */
    stack_pos = stack_pos - 1;
    type = 3;
  }
  return type;
}

/*
 * type-name:
 *     char *
 *     int
 */
void type_name()
{
  get_token();
  while (accept("*")) {
  }
}

/*
 * statement:
 *     { statement-list-opt }
 *     type-name identifier ;
 *     type-name identifier = expression;
 *     if ( expression ) statement
 *     if ( expression ) statement else statement
 *     while ( expression ) statement
 *     return ;
 *     expr ;
 */
void statement()
{
  int p1;
  int p2;
  if (accept("{")) {
    int n = table_pos;
    int s = stack_pos;
    while (accept("}") == 0)
      statement();
    table_pos = n;
    be_pop(stack_pos - s);
    stack_pos = s;
  }
  else if (peek("char") | peek("int")) {
    type_name();
    sym_declare(token, 'L', stack_pos);
    get_token();
    if (accept("="))
      promote(expression());
    expect(";");
    be_push();
    stack_pos = stack_pos + 1;
  }
  else if (accept("if")) {
    expect("(");
    promote(expression());
    emit(4, "\x00\x00\x50\xe3"); /* cmp r0, #0 */
    p1 = codepos;
    emit(4, "\x00\x00\x00\x0a"); /* test %eax,%eax ; je ... */ /* beq else */ /* TODO check overflow */
    expect(")");
    statement();
    p2 = codepos;
    emit(4, "\x00\x00\x00\xea"); /* jmp ... */ /* b end */ /* TODO check overflow */
    save_int(code + p1, (((codepos - 8 - p1)>>2) & 16777215) + 167772160); /* 16777215 = 0x00ffffff, 167772160 = 0x0a000000 */
    if (accept("else"))
      statement();
    save_int(code + p2, (((codepos - 8 - p2)>>2) & 16777215) + 3925868544); /* 16777215 = 0x00ffffff, 3925868544 = 0xea000000 */
  }
  else if (accept("while")) {
    expect("(");
    p1 = codepos;
    promote(expression());
    emit(4, "\x00\x00\x50\xe3"); /* cmp r0, #0 */
    p2 = codepos;
    emit(4, "\x00\x00\x00\x0a"); /* test %eax,%eax ; je ... */ /* beq end */ /* TODO check overflow */
    expect(")");
    statement();
    emit(4, "\x00\x00\x00\xea"); /* jmp ... */ /* b begin */ /* TODO check overflow */
    save_int(code + codepos - 4, (((p1 - (codepos - 4) - 8)>>2) & 16777215) + 3925868544); /* 16777215 = 0x00ffffff, 3925868544 = 0xea000000 */
    save_int(code + p2, (((codepos - 8 - p2)>>2) & 16777215) + 167772160); /* 16777215 = 0x00ffffff, 167772160 = 0x0a000000 */
  }
  else if (accept("return")) {
    if (peek(";") == 0)
      promote(expression());
    expect(";");
    be_pop(stack_pos);
    emit(4, "\x00\x80\xbd\xe8"); /* ret */ /* ldmfd sp!, {pc} */
  }
  else {
    expression();
    expect(";");
  }
}

/*
 * program:
 *     declaration
 *     declaration program
 *
 * declaration:
 *     type-name identifier ;
 *     type-name identifier ( parameter-list ) ;
 *     type-name identifier ( parameter-list ) statement
 *
 * parameter-list:
 *     parameter-declaration
 *     parameter-list, parameter-declaration
 *
 * parameter-declaration:
 *     type-name identifier-opt
 */
void program()
{
  int current_symbol;
  while (token[0]) {
    type_name();
    current_symbol = sym_declare_global(token);
    get_token();
    if (accept(";")) {
      sym_define_global(current_symbol);
      emit(4, "\x00\x00\x00\x00");
    }
    else if (accept("(")) {
      int n = table_pos;
      number_of_args = 0;
      while (accept(")") == 0) {
        number_of_args = number_of_args + 1;
        type_name();
        if (peek(")") == 0) {
          sym_declare(token, 'A', number_of_args);
          get_token();
        }
        accept(","); /* ignore trailing comma */
      }
      if (accept(";") == 0) {
        sym_define_global(current_symbol);
        emit(4, "\x00\x40\x2d\xe9"); /* stmfd sp!, {lr} */
        statement();
        emit(4, "\x00\x80\xbd\xe8"); /* ret */ /* ldmfd sp!, {pc} */
      }
      table_pos = n;
    }
    else
      error();
  }
}

int main1()
{
  code_offset = 32768; /* 0x8000 */
  be_start();
  nextc = getchar();
  get_token();
  program();
  be_finish();
  return 0;
}
