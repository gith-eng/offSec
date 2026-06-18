00_guestbook:
  With checksec --file=./guestbook we see that the program has no canary, no PIE, NX enabled. 
  Main reads 256B into 64B buffer. Buffer overflow is possible. 
  We need to find offset to RIP (by sendind a cyclic input), ret gadget address (ROPgadget --binary ./guestbook  | grep ": ret$"). The win function is in main.

01_whispered_secrets:
  No canary, no PIE, no NX enabled.
  Program prints buf address, then reads 1024B into 128B buf.
  Since no NX we can write shellcode into buf and then put buf address into RIP to execute it.

02_escape_room:
  No canary, no PIE, NX enabled.
  Program reads unchecked input into 64B buffer.
  We need to use two gadgets to set the arguments we want, and then call win function.

03_lemonade_stand:
  No canary, PIEenabled, NX enabled.
  Program reads unchecked buffer into buf, then prints current price. 
  We can use cyclic input to get price offset, then overwrite it with correct price.

04_mini_game:
  No canary, no PIE, NX enabled.
  Program stores function pointer on stack, then reads as input an unchecked buffer.
  We can overwrite the function pointer to point at the winning function instead of the standard one.

05_cosmic_burger:
  No canary, PIE enabled, NX enabled.
  Program prints the current values of cheese and sauce, reads unchecked input into 32B buf, then prints new cheese and sauce values.
  We can get offset for cheese and sauce and then overwrite them with correct values.
