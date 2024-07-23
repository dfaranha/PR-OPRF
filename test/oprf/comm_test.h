#ifndef COMM_TEST_H
#define COMM_TEST_H

uint64_t comm(BoolIO<NetIO> *ios[1]) {
	uint64_t c = 0;
	for(int i = 0; i < 1; ++i)
		c += ios[i]->counter;
	return c;
}
uint64_t comm2(BoolIO<NetIO> *ios[1]) {
	uint64_t c = 0;
	for(int i = 0; i < 1; ++i)
		c += ios[i]->io->counter;
	return c;
}

#endif