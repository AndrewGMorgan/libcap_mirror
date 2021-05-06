all: su

su: su.c
	$(CC) -o $@ $< -lpam -lpam_misc -lcap
	sudo chown root ./su
	sudo chmod +s ./su

clean:
	rm -f su su.o *~
