# sys_call_checksum
Sha256 the system call table on a x86_64 Linux machine

I know this "defence" has its weaknesses but inserted to run
at initramfs with centralised logging it can prove to be useful
in certain environments that you might not be able to replatform
or replatform quickly. Was mostly an exercise in better understanding Linux internals and code.
A beer owed to vrasneur@free.fr for the code I have reused, thanks for publishing yours it was helpful to learn from.
Also thanks to 0xAX for linux-insides as it helped me appreciate a lot.
