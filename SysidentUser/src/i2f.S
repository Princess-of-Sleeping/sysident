
	.align 4
	.text
	.cpu cortex-a9
	.arch armv7-a
	.syntax unified
	.thumb
	.thumb_func
	.fpu neon

	.global i2f
	.type   i2f, %function

@ int i2f(float *dst, uint32_t val);

i2f:
	// 1024
	movs r3, #0
	movt r3, #0x4480

	vmov s0, r3

	vmov s1, r1
	vcvt.f32.u32 s1, s1

	vdiv.f32 s0, s1, s0

	vstr s0, [r0]

	bx lr

	.data
