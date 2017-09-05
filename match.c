/* Copyright © 1997—1999 Thomas Boutell <boutell@boutell.com>
                         and Boutell.Com, Inc.
             © 2003—2017 Sam Hocevar <sam@hocevar.net>

   This software is released for free use under the terms of
   the GNU Public License, version 2 or higher. NO WARRANTY
   IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK. */

#if HAVE_CONFIG_H
   #include <config.h>
#endif

#include <string.h>
#include <ctype.h>
#include "match.h"

int match(char const *sorig, char const *p)
{
	return matchBody(sorig, p, 0);
}

int matchNoCase(char const *sorig, char const *p)
{
	return matchBody(sorig, p, 1);
}

#define CASE(x) (nocase ? tolower(x) : (x))

int matchBody(char const *sorig, char const *p, int nocase)
{
	/* Algorithm:

		Word separator: *. End-of-string
		is considered to be a word constituent.
		? is similarly considered to be a specialized
		word constituent.

		Match the word to the current position in s.
		Empty words automatically succeed.

		If the word matches s, and the word
		and s contain end-of-string at that
		point, return success.

		\ escapes the next character, including \ itself (6.0).

		For each *:

			Find the next occurrence of the next word
			and advance beyond it in both p and s.
			If the next word ends in end-of-string
			and is found successfully, return success,
			otherwise advance past the *.

			If the word is not found, return failure.

			If the next word is empty, advance past the *.

		Behavior of ?: advance one character in s and p.

		Addendum: consider the | character to be a logical OR
		separating distinct patterns. */

	char const *s = sorig;
	int escaped = 0;
	while (1) {
		char const *word;
		int wordLen;
		int wordPos;
		if (escaped) {
			/* This is like the default case,
				except that | doesn't end the pattern. */
			escaped = 0;
			if ((*s == '\0') && (*p == '\0')) {
				return 1;
			}
			if (CASE(*p) != CASE(*s)) {
				goto nextPattern;
			}
			p++;
			s++;
			continue;
		}
		switch(*p) {
			case '\\':
			/* Escape the next character. */
			escaped = 1;
			p++;
			continue;
			case '*':
			/* Find the next occurrence of the next word
				and advance beyond it in both p and s.
				If the next word ends in end-of-string
				and is found successfully, return success,
				otherwise advance past the *.

				If the word is not found, return failure.

				If the next word is empty, advance. */
			p++;
			wordLen = 0;
			word = p;
			while (1) {
				if ((*p) == '*') {
					break;
				}
				wordLen++;
				if ((*p == '\0') || (*p == '|')) {
					break;
				}
				p++;
			}
			wordPos = 0;
			while (1) {
				if (wordPos == wordLen) {
					if ((*p == '\0') || (*p == '|')) {
						return 1;
					}
					break;
				}
				if ((((CASE(*s)) == CASE(word[wordPos])) ||
					((*s == '\0') &&
						(word[wordPos] == '|'))) ||
					(((*s != '\0') && (*s != '|')) &&
						(word[wordPos] == '?')))
				{
					wordPos++;
					s++;
				} else {
					s -= wordPos;
					if (!(*s)) {
						goto nextPattern;
					}
					s++;
					wordPos = 0;
				}
			}
			break;
			case '?':
			p++;
			s++;
			break;
			default:
			if ((*s == '\0') && ((*p == '\0') ||
				(*p == '|'))) {
				return 1;
			}
			if (CASE(*p) != CASE(*s)) {
				goto nextPattern;
			}
			p++;
			s++;
			break;
		}
		continue;
nextPattern:
		while (1) {
			if (*p == '\0') {
				return 0;
			}
			if (*p == '|') {
				p++;
				s = sorig;
				break;
			}
			p++;
		}
	}
}

#ifdef TEST_MATCH

#include <stdio.h>
#include <string.h>
#include <ctype.h>

int main(int argc, char *argv[])
{
	char s[1024];
	if (argc != 2) {
		fprintf(stderr, "Usage: match pattern\n");
		return 1;
	}
	while (1) {
		if (!fgets(s, sizeof(s), stdin)) {
			break;
		}
		while (isspace(s[strlen(s) - 1])) {
			s[strlen(s) - 1] = '\0';
		}
		printf("%s --> %s\n", s, argv[1]);
		if (match(s, argv[1])) {
			printf("Match\n");
		} else {
			printf("No Match\n");
		}
	}
}

#endif /* TEST_MATCH */

