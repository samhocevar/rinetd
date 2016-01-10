#ifndef MATCH_H
#define MATCH_H 1

extern int match(char const *s, char const *p);
extern int matchNoCase(char const *s, char const *p);
extern int matchBody(char const *s, char const *p, int nocase);

#endif /* MATCH_H */

