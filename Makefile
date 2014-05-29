##
## Makefile for tsps
## by lenormf
##

NAME = tsps

SRC = tsps.c
OBJ = $(SRC:.c=.o)

CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS =

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(NAME): $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) -o $@

all: $(NAME)

clean:
	rm -f $(OBJ)

distclean: clean
	rm -f $(NAME)

re: distclean all

debug:
	@make NAME=$(NAME)_debug CFLAGS="$(CFLAGS) -ggdb -DDEBUG" re
