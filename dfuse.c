/*
 * Code not otherwise copyrighted is Copyright (C) 2010-2011 Dan Reif/BlackMesh Managed Hosting.
 * This is version 0.4a.
 * 
 * With the permission of Miklos Szeredi, the entirety of this file is exclusively licensed
 * under the GNU GPL, version 2 or later:
 *
 * DFUSE, (C) Dan Reif, Miklos Szeredi, and others, based on the Hello FS template by Miklos
 * Szeredi <miklos@szeredi.hu>.  This code and any resultant executables or libraries are
 * governed by the terms of the GPL published by the GNU project of the Free Software
 * Foundation, either version 2, or (at your option) the latest version available at
 * www.gnu.org at the time of its use or modification.
 */

/*
 * CHANGELOG:
 * 0.1a djr@BM: Initial Alpha
 * 0.2a djr@BM: Fix crash on NULL data, add symlink representation of NULL, rename some functions.
 * 0.3a djr@BM: Added "--json" mode.
 * 0.3.1a djr@BM: Fixed a couple things that were bugging the hell out of me: embedded NULLs in
 *                primary keys now work properly, we test for successful DB connection at
 *                invocation (though I think I could do a better job of displaying the errors),
 *                and there was a bunch of extra bounds-checking added.  Oh, and put more stuff
 *                into #defines that belongs there instead of as magic numbers.
 * 0.3.2a djr@BM: Found and fixed a memory leak.
 * 0.3.3a djr@BM: Changed license to GPL v2+.
 * Subsequent versions: See https://github.com/bmdan/dfuse
 */

#define FUSE_USE_VERSION 25

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <my_global.h>
#include <my_sys.h>
#include <mysql.h>
#include <errmsg.h>
#include <fuse_opt.h>
#include <syslog.h>

/** options for fuse_opt.h */
struct options {
    char *username;
    char *password;
    char *hostname;
    char *database;
    char *table;
    char *prikey;
    char *columns;
    char *timestamp;
}options;

//Conservative, yes, but should be plenty.  Also protects us from signedness issues.
#define MAX_STRING_LENGTH 2147483646

struct string_length {
    char * string;
    unsigned long length;
};

struct dfuse_nv_ll {
    struct string_length * name;
    struct string_length * value;
    struct dfuse_nv_ll * nvll_value;
    struct dfuse_nv_ll * next;
};

FILE *debug_fd( void );

#ifdef DEBUG
#define D(x,y) {fprintf(debug_fd(),(x),(y));fflush(debug_fd());}
#else
#define D(x,y) (void)0
#endif

// Stands for "DFuse Return Value".  Implements --lazy-connect.  Use instead of "return (somevalue);".
#define DFRV(v) { dfuse_maybe_close(); return (v); }

#define MYSQLSERVER options.hostname
#define MYSQLUSER options.username
#define MYSQLPASS options.password
#define MYSQLDB options.database

#define MAX_SQL_LENGTH 1500

//Doesn't like 'A', prefers 'a'.  Makes the algorithm faster.
#define FROM_HEX(nbl) (((nbl)-'0')%('a'-'0'-10))

/** macro to define options */
#define DFUSE_OPT_KEY(t, p, v) { t, offsetof(struct options, p), v }

/** keys for FUSE_OPT_ options */
enum
{
    KEY_VERSION,
    KEY_HELP,
    KEY_LAZY_CONNECT,
    KEY_FOREGROUND,
    KEY_JSON,
};

static struct fuse_opt dfuse_opts[] =
{
    DFUSE_OPT_KEY("-u %s", username, 0),
    DFUSE_OPT_KEY("-p %s", password, 0),
    DFUSE_OPT_KEY("-H %s", hostname, 0),
    DFUSE_OPT_KEY("-D %s", database, 0),
    DFUSE_OPT_KEY("-t %s", table, 0),
    DFUSE_OPT_KEY("-P %s", prikey, 0),
    DFUSE_OPT_KEY("-c %s", columns, 0),
    DFUSE_OPT_KEY("-T %s", timestamp, 0),

    // #define FUSE_OPT_KEY(templ, key) { templ, -1U, key }
    FUSE_OPT_KEY("-V",			KEY_VERSION),
    FUSE_OPT_KEY("--version",		KEY_VERSION),
    FUSE_OPT_KEY("-h",			KEY_HELP),
    FUSE_OPT_KEY("--help",		KEY_HELP),
    FUSE_OPT_KEY("--lazy-connect",	KEY_LAZY_CONNECT),
    FUSE_OPT_KEY("--foreground",	KEY_FOREGROUND),
    FUSE_OPT_KEY("-f",			KEY_FOREGROUND),
    FUSE_OPT_KEY("--json",		KEY_JSON),
    FUSE_OPT_END
};

MYSQL *cached_sql = NULL;
MYSQL *dfuse_connect( char *host, char *user, char *pass, char *defaultdb );
FILE *cached_debug_fd = NULL;
void usage( char **argv );
unsigned short int lazy_conn = 0;
unsigned short int json = 0;

#ifdef VMALLOC
//No support for calloc, realloc... it's a hack, replace it with something better.

/* Compile with -DVMALLOC and -DDEBUG to enable.  Try something like:
 * grep -i alloc /tmp/fusedebug | awk '/Dealloc/ {print $2} /Alloc/ {print $7}' | sort | uniq -c | sort -rn
 * to parse it, though really what you want is more like:
 * grep -i alloc /tmp/fusedebug | awk '/Dealloc/ {print $2} /Alloc/ {print $7}' | sort | uniq -c | grep -vE '[02468] '
 * though that's not tested.  The first syntax found me the fact that I never free()'d encoded_prikey in
 * dfuse_jsonify_row.  Oops!
 */

void * dfuse_malloc( size_t s, long line )
{
    void * p = NULL;

    D("Allocating %d bytes at ", (s));
    D("line %ld: ",line);
    p = malloc(s);
    D("%p\n",p);
    return p;
}

void dfuse_free( void * p, long line )
{
    D("Deallocating %p at ", (p));
    D("line %ld.\n",line);
    free(p);
}

#define DFUSE_MALLOC(s) dfuse_malloc((s),__LINE__)
#define DFUSE_FREE(p) dfuse_free((p),__LINE__)

#else

#define DFUSE_MALLOC(s) malloc((s))
#define DFUSE_FREE(p) free((p))

#endif

static char hex[] = "0123456789abcdef";

//I couldn't find a decent one, so I wrote my own.  It's frankly proud of the fact that it ignores locales.
//I can't come up with a reason why that's not the right decision here, but if I'm wrong, feel free to correct it.
char *urlencode( const char *encodethis, unsigned long length )
{
    unsigned long i, rvptr = 0;
    char *rv;

    if ( !length || !encodethis )
    {
	return NULL;
    }

    if ( length > MAX_STRING_LENGTH )
    {
	//Arguably should die here.
	return NULL;
    }

    if ( !( rv = DFUSE_MALLOC(length*3+1) ) ) //Allocate for the malicious case: every single character needs to be escaped.
    {
	return NULL;
    }

    D("Encoding '%s': ",encodethis);

    for ( i = 0; i < length; i++ )
    {
	if ( ( encodethis[i] >= 'A' && encodethis[i] <= 'Z' ) //[A-Z], aka isupper() but paranoid
	  || ( encodethis[i] >= 'a' && encodethis[i] <= 'z' ) //[a-z], aka islower() but paranoid
	  || ( encodethis[i] >= '0' && encodethis[i] <= '9' ) //[0-9], ala isdigit() but paranoid
	  || ( encodethis[i] == '-' || encodethis[i] == '_' || encodethis[i] == '.' || encodethis[i] == ':' ) ) //Exceptions
	{
	    rv[rvptr++] = encodethis[i];
	    continue;
	}

	rv[rvptr++] = '%';
	rv[rvptr++] = hex[(encodethis[i] >> 4) & 0x0f];
	rv[rvptr++] = hex[(encodethis[i] ) & 0x0f];

	if ( rvptr >= MAX_STRING_LENGTH )
	{
	    DFUSE_FREE(rv);
	    return NULL;
	}
    }

    rv[rvptr] = '\0';

    D("'%s'.\n",rv);

    return rv;
}

struct string_length *htmldecode_n( const char *decodethis, struct string_length *rv_struct, unsigned long maxi )
{
    unsigned long i, rvptr = 0;
    char *rv;

    D( "Decoding '%s'.\n", decodethis );

    if ( !rv_struct || !rv_struct->string || !decodethis || maxi < 0 ) //We explicitly *do* handle zero-length strings.
    {
        return NULL;
    }

    if ( maxi >= MAX_STRING_LENGTH )
    {
        //Arguably should die here.
        return NULL;
    }

    rv = rv_struct->string;

    for ( i = 0; i <= maxi; i++ )
    {
        if ( decodethis[i] != '&' )
        {
	    rv[rvptr++] = decodethis[i];
	    continue;
	}

	if ( decodethis[i+1] != 'x' )
	{
	    D( "Failed 'x' assert at i=%ld.", i );
	    return NULL;
	}

	if ( decodethis[i+4] != ';' )
	{
	    D( "Failed ';' assert at i=%ld.", i );
	    return NULL;
	}

	rv[rvptr++] = (FROM_HEX(decodethis[i+2])<<4) + FROM_HEX(decodethis[i+3]);

	i += 4;

	if ( rvptr >= MAX_STRING_LENGTH ) // This can never happen, since rvptr is always <= strlen(decodethis), but meh
	{
	    return NULL;
	}
    }

    rv[rvptr] = '\0';

    rv_struct->length = rvptr;

    return rv_struct;
}

char *htmlencode( const char *encodethis, unsigned long length )
{
    unsigned long i, rvptr = 0;
    char *rv;

    if ( length < 0 || !encodethis )
    {
	return NULL;
    }

    if ( length > MAX_STRING_LENGTH )
    {
	//Arguably should die here.
	return NULL;
    }

    if ( !( rv = DFUSE_MALLOC(length*5+1) ) ) //Allocate for the malicious case: every single character needs to be escaped.
    {
	return NULL;
    }

    D("Encoding '%s': ",encodethis);

    for ( i = 0; i < length; i++ )
    {
	if ( ( encodethis[i] >= 'A' && encodethis[i] <= 'Z' ) //[A-Z], aka isupper() but paranoid
	  || ( encodethis[i] >= 'a' && encodethis[i] <= 'z' ) //[a-z], aka islower() but paranoid
	  || ( encodethis[i] >= '0' && encodethis[i] <= '9' ) //[0-9], ala isdigit() but paranoid
	  || ( encodethis[i] == '-' || encodethis[i] == '_' || encodethis[i] == '.' || encodethis[i] == ':' ) || encodethis[i] == ' ' ) //Exceptions
	{
	    rv[rvptr++] = encodethis[i];
	    continue;
	}

	rv[rvptr++] = '&';
	rv[rvptr++] = 'x';
	rv[rvptr++] = hex[(encodethis[i] >> 4) & 0x0f];
	rv[rvptr++] = hex[(encodethis[i] ) & 0x0f];
	rv[rvptr++] = ';';

	if ( rvptr >= MAX_STRING_LENGTH )
	{
	    DFUSE_FREE(rv);
	    return NULL;
	}
    }

    rv[rvptr] = '\0';

    D("'%s'.\n",rv);

    return rv;
}

/*
 * Doesn't handle some old-style silliness (like +), but meh.  The real trick
 * here is that, since I control what gets generated as a name in the first
 * place, I can take some shortcuts.  A significant security risk downside to
 * that line of thinking is that it permits multiple representations of a
 * given file's name; for example, you can call a file "cron_last", but you can
 * reference that same file as "cro%6e_last", and perhaps most surprisingly, as
 * "cro%]e_last".  If that poses a security concern, it's easy enough to do
 * something like urlencode(rv) and then strcmp it to what you were handed in
 * the first place, but since the whole point of this approach is speed, I
 * didn't see a need to do that.  If you're exposing this dir via Apache with
 * <File> directives governing access, you'll probably want to add that strcmp.
 */
struct string_length *urldecode( const char *decodethis )
{
    unsigned long i, rvptr = 0;
    char *rv;
    struct string_length * rv_struct = NULL;

    /*
     * Zero-length strings freak me out here, but there's no reason to refuse to decode them
     * that I can think of.  Convince me otherwise.
     */
    if ( !decodethis )
    {
	return NULL;
    }

    if ( strlen(decodethis) >= MAX_STRING_LENGTH )
    {
	//Arguably should die here.
	return NULL;
    }

    if ( !( rv = DFUSE_MALLOC( strlen(decodethis)+1 ) ) )
    {
	return NULL;
    }

    for ( i = 0; i < strlen(decodethis); i++ )
    {
	if ( decodethis[i] != '%' )
	{
	    rv[rvptr++] = decodethis[i];
	    continue;
	}

	rv[rvptr++] = (FROM_HEX(decodethis[i+1])<<4) + FROM_HEX(decodethis[i+2]);

	i += 2;

	if ( rvptr >= MAX_STRING_LENGTH ) // This can never happen, since rvptr is always <= strlen(decodethis), but meh
	{
	    DFUSE_FREE( rv );
	    return NULL;
	}
    }

    rv[rvptr] = '\0';

    if ( !( rv_struct = DFUSE_MALLOC( sizeof( rv_struct ) ) ) )
    {
	DFUSE_FREE( rv );
	return NULL;
    }

    rv_struct->length = rvptr;
    rv_struct->string = rv;

    return rv_struct;
}

void dfuse_maybe_close( void )
{
    if ( !cached_sql || !lazy_conn )
    {
	return;
    }

    mysql_close( cached_sql );
    cached_sql = NULL;

    return;
}

char * dfuse_jsonify_row( MYSQL_ROW *sql_row, MYSQL_RES *sql_res, char *prikey, unsigned long prikey_len )
{
    char **encoded_pieces, **encoded_fieldname, *encoded_prikey, *rv;
    MYSQL_FIELD *sql_field;
    unsigned long *lengths;
    unsigned int num_fields, i;
    unsigned long encoded_length = 0;
    unsigned long long jsonified_length = 0;
    static char jsonify_prepri[] = "{\n\t\"";
    static char jsonify_postpri[] = "\": {\n";
    static char jsonify_prerow[] = "\t\"";
    static char jsonify_midrow[] = "\": \"";
    static char jsonify_midrow_nq[] = "\": ";
    static char jsonify_postrow[] = "\",\n";
    static char jsonify_postrow_nq[] = ",\n";
    static char jsonify_end[] = "\t}\n}";

    if ( !sql_row || !prikey )
    {
	return NULL;
    }

    if ( prikey_len > MAX_STRING_LENGTH )
    {
	//Arguably should die here.
	return NULL;
    }

    if ( !( num_fields = mysql_num_fields( sql_res ) ) )
    {
	return NULL;
    }

    if ( !( lengths = mysql_fetch_lengths( sql_res ) ) )
    {
	return NULL;
    }

    if ( !( encoded_prikey = htmlencode(prikey, prikey_len) ) )
    {
	return NULL;
    }

    if ( !( encoded_pieces = DFUSE_MALLOC(sizeof(encoded_pieces)*num_fields) ) )
    {
	return NULL;
    }

    if ( !( encoded_fieldname = DFUSE_MALLOC(sizeof(encoded_fieldname)*num_fields) ) )
    {
	return NULL;
    }

    for ( i = 0; i < num_fields; i++ )
    {
	sql_field = mysql_fetch_field( sql_res );

	if ( sql_field && sql_field->name )
	{
	    encoded_fieldname[i] = htmlencode(sql_field->name,sql_field->name_length);
	}
	else
	{
	    encoded_fieldname[i] = "";
	}
	encoded_length += strlen(encoded_fieldname[i]);

	D("Got an encoded fieldname: '%s'.\n", encoded_fieldname[i]);

	if ( (*sql_row)[i] )
	{
	    encoded_pieces[i] = htmlencode((*sql_row)[i],lengths[i]);
	    encoded_length += strlen(encoded_pieces[i]);
	}
	else
	{
	    D("\tDecided to null-code: '%p', ", sql_row[i]);
	    D("'%p'\n", (*sql_row)[i]);
	    encoded_pieces[i] = NULL;
	    encoded_length += strlen("null")-
		((strlen(jsonify_midrow)+strlen(jsonify_postrow))-
		 (strlen(jsonify_midrow_nq)+strlen(jsonify_postrow_nq))); // -2 for the start and end quotes.
	}

	D("\tBuilt an encoded_piece: '%s'.\n", encoded_pieces[i]);
    }

    jsonified_length = (
	strlen( jsonify_prepri ) +
	strlen( encoded_prikey ) +
	strlen( jsonify_postpri ) +
	( ( strlen( jsonify_prerow ) + strlen( jsonify_midrow ) + strlen( jsonify_postrow ) ) * num_fields ) +
	encoded_length +		// length of all the row data and field names, htmlencoded
	strlen( jsonify_end ) +
	1 );				// '\0'

    if ( jsonified_length > MAX_STRING_LENGTH )
    {
	//Arguably should die noisily, since this means skullduggery is almost certainly afoot.
	for ( i = 0; i < num_fields; i++ )
	{
	    DFUSE_FREE( encoded_fieldname[i] );
	    DFUSE_FREE( encoded_pieces[i] );
	}
	DFUSE_FREE( encoded_fieldname );
	DFUSE_FREE( encoded_pieces );
	DFUSE_FREE( encoded_prikey);
	return NULL;

    }

    //Opportunity to optimize: cache strlen()s via #define or summat
    if ( !jsonified_length || !( rv = DFUSE_MALLOC( jsonified_length ) ) )
    {
	for ( i = 0; i < num_fields; i++ )
	{
	    DFUSE_FREE( encoded_fieldname[i] );
	    DFUSE_FREE( encoded_pieces[i] );
	}
	DFUSE_FREE( encoded_fieldname );
	DFUSE_FREE( encoded_pieces );
	DFUSE_FREE( encoded_prikey);
	return NULL;
    }

    // This part is stupidly easy to optimize; parts of the rv string are copied over themselves (row+1) times.

    D("Got a rv ready to bundle with e_l = %ld.\n",encoded_length);

    sprintf( rv, "%s%s%s",
	jsonify_prepri,
	encoded_prikey,
	jsonify_postpri );

    D("Starting off small: '%s'.\n", rv);

    for ( i = 0; i < num_fields; i++ )
    {
	sprintf( rv, "%s%s%s%s%s%s",
	    rv,
	    jsonify_prerow,
	    encoded_fieldname[i],
	    encoded_pieces[i] ? jsonify_midrow : jsonify_midrow_nq,
	    encoded_pieces[i] ? encoded_pieces[i] : "null",		//The irony that "null" goes in quotes here of
	    encoded_pieces[i] ? jsonify_postrow : jsonify_postrow_nq ); //all places is not lost on me.

	DFUSE_FREE( encoded_fieldname[i] );
	DFUSE_FREE( encoded_pieces[i] );

	D("Gettin' fancier: '%s'.\n", rv);
    }

    sprintf( rv, "%s%s",
	rv,
	jsonify_end );

    D("Slicker 'n a mayonaise sandwich: '%s'.\n", rv);

    DFUSE_FREE( encoded_fieldname );
    DFUSE_FREE( encoded_pieces );
    DFUSE_FREE( encoded_prikey);

    return rv;

/*  Pseudocode to help me get things right.
    $rv = "{\n\t" . prikey . ": {\n";

    foreach( $row as $key => $val )
    {
	$rv .= "\t" . $key . ': "' . htmlencode($val) . '",' . "\n";
    }

    $rv .= "\t}\n}";
*/
}


struct dfuse_nv_ll * new_nvll( void )
{
    struct dfuse_nv_ll *rv;

    if ( !( rv = DFUSE_MALLOC( sizeof( struct dfuse_nv_ll ) ) ) )
    {
	return NULL;
    }

    rv->name = NULL;
    rv->nvll_value = NULL;
    rv->value = NULL;
    rv->next = NULL;

    return rv;
}

void free_nvll( struct dfuse_nv_ll *root )
{
    if ( !root )
    {
	return;
    }

    if ( root->name ) { DFUSE_FREE(root->name); }
    if ( root->value ) { DFUSE_FREE(root->value); }
    if ( root->nvll_value ) { free_nvll( root->nvll_value ); }
    if ( root->next ) { free_nvll( root->next ); }

    DFUSE_FREE( root );
}

#define so_sl sizeof( struct string_length )

/*
 * Parses some JSON into an array for you.
 *
 * @param json The string to parse.  Must be complete and valid JSON, and cannot omit the
 *   root {} (that said, it might actually work, but I can't promise anything).
 * @param recursed If it is non-null, we will return as soon as paren_deep <= 0 and set the
 *   unsigned long to which it points to the number of characters we disgested (intended
 *   for internal use; by default, we error out when the json is invalid, and this test is
 *   one of the ways we know that it is.
 *
 * @returns A linked list, next == null on the last element.
 */
struct dfuse_nv_ll * dfuse_parse_json( const char *json, size_t size, unsigned long *recursed )
{
    struct dfuse_nv_ll *rootnvll = NULL;
    struct dfuse_nv_ll *thisnvll = NULL;

    unsigned long i;
    unsigned long chars;
    unsigned long toallocate;
    int paren_deep = 0;

    short int gotaname = 0;

    char *decodedval;
    struct string_length *decodedsl;

    if ( !json )
    {
	D( "Null json with recursed='%p'.", recursed );
	return NULL;
    }

    // We'll do this inside the loop, instead.  Might be faster to do it here, though.  Feel
    // free to benchmark both approaches.
/*    if ( strlen(json) > MAX_STRING_LENGTH )
    {
	return NULL;
    }*/

    for ( i = 0; json[i] != '\0' && i < size; i++ )
    {
	D( "\nParsing '%c'.\n", json[i] );

	switch( json[i] )
	{
	    case ' ':
	    case '\t':
	    case '\n':
	    case '\r':
	    case ',': //We skip it; arguably, we should parse through it, but that really only adds an extra error check.
	    case ':': //As above.
		continue;
	    case '"':
		if ( !rootnvll || !thisnvll )
		{
		    D( "Reading a string without any rootnvll and/or thisnvll.  Dying at %d.", __LINE__ );
		    return NULL;
		}

		// Read until endquote, this is our name if name==null, our value otherwise.
		// If it's a value, when done reading it, set name=null.
		toallocate=1; //sizeof("") = 1 due to '\0'.

		for ( chars = 1; json[i+chars] != '"'; chars++ )
		{
		    toallocate++;

		    if ( json[i+chars] == '\0' )
		    {
			D( "Unexpected null while reading nameval at pos %ld.", i+chars );
			free_nvll( rootnvll );
			return NULL;
		    }

		    if ( json[i+chars] == '&' )
		    {
			if ( json[i+chars+1] != 'x'
			  || json[i+chars+4] != ';' )
			{
			    D( "Bad '&' at position %ld.", i+chars );
			    free_nvll( rootnvll );
			    return NULL;
			}

			D( "Read an entity at i=%ld.", i );

			chars += 4; // skip this character and the next four.
			continue;
		    }
		}

		if ( !( decodedsl = DFUSE_MALLOC(sizeof(decodedsl)) ) )
		{
		    D( "Failed to allocate %ld bytes for decodedsl.", sizeof(decodedsl) );
		    free_nvll(rootnvll);
		    return NULL;
		}

		if ( !( decodedval = DFUSE_MALLOC(toallocate) ) )
		{
		    D( "Failed to allocate %ld bytes for toallocate.", toallocate );
		    free_nvll(rootnvll);
		    DFUSE_FREE(decodedsl);
		    return NULL;
		}

		decodedsl->string = decodedval;
		decodedsl->length = 0;

		if ( chars == 1 ) //In other words, if the first character we hit was a "...
		{
			decodedsl->string[0] = '\0';
		}
		else if ( !htmldecode_n( json+i+1, decodedsl, chars-2 ) )
		{
		    D( "Chars = %ld", chars );
		    D( "Failed to htmldecode at line %d.", __LINE__ );
		    free_nvll(rootnvll);
		    DFUSE_FREE(decodedval);
		    DFUSE_FREE(decodedsl);
		    return NULL;
		}

		// -1 for the '\0'
		if ( (toallocate-1) != decodedsl->length )
		{
		    D( "Assert failed; my size estimation was wrong!  They differ by %ld.", toallocate-1-decodedsl->length );
		    free_nvll(rootnvll);
		    DFUSE_FREE(decodedval);
		    DFUSE_FREE(decodedsl);
		    return NULL;
		}

		if ( gotaname )
		{
		    if ( !( thisnvll->value = DFUSE_MALLOC( sizeof( thisnvll->value ) ) ) )
		    {
			D( "Failed to malloc for the value stringlength at i=%ld.", i );
			free_nvll(rootnvll);
		        DFUSE_FREE(decodedval);
		        DFUSE_FREE(decodedsl);
			return NULL;
		    }

		    thisnvll->value->length = toallocate-1;
		    thisnvll->value->string = decodedsl->string;

		    DFUSE_FREE( decodedsl );

		    gotaname = 0;
		}
		else
		{
		    struct dfuse_nv_ll *lastnvll = thisnvll;

		    if ( !( thisnvll = new_nvll() ) )
		    {
			D( "Failed to malloc for new thisnvll at %d.", __LINE__ );
			free_nvll(rootnvll);
			DFUSE_FREE(decodedval);
			DFUSE_FREE(decodedsl);
			return NULL;
		    }

		    lastnvll->next = thisnvll;

		    if ( !( thisnvll->name = DFUSE_MALLOC( sizeof( thisnvll->name ) ) ) )
		    {
			D( "Failed to malloc for the name stringlength at i=%ld.", i );
			free_nvll(rootnvll);
		        DFUSE_FREE(decodedval);
		        DFUSE_FREE(decodedsl);
			return NULL;
		    }

		    thisnvll->name->length = toallocate-1;
		    thisnvll->name->string = decodedsl->string;

		    DFUSE_FREE( decodedsl );

		    gotaname = 1;
		}

		i += chars;
		break;
	    case '{':
		paren_deep++;

		if ( !rootnvll )
		{
		    if ( paren_deep > 1 )
		    {
			D( "Things that should never happen, part 6(b), subsection %d.", __LINE__ );
			return NULL;
		    }
		    //Root brace.  Or misformatted JSON.  Either way, don't get too worked up over it.
		    if ( !( rootnvll = thisnvll = new_nvll() ) )
		    {
			D( "Bailing due to inability to set rootnvll to newnvll at %d.", __LINE__ );
			return NULL;
		    }
		    continue;
		}

		if ( !gotaname || !thisnvll->name )
		{
		    D( "Things that should never happen, part 6(b), subsection %d.", __LINE__ );
		    free_nvll( rootnvll );
		    return NULL;
		}

		if ( thisnvll->value )
		{
		    D( "Things that should never happen, part 6(b), subsection %d.", __LINE__ );
		    free_nvll( rootnvll );
		    return NULL;
		}

		if ( !( thisnvll->nvll_value = dfuse_parse_json( json+i, size-i, &chars ) ) )
		{
		    D( "Things that should never happen, part 6(b), subsection %d.", __LINE__ );
		    free_nvll( rootnvll );
		    return NULL;
		}

		i += chars-1; //We want to be handed back the location of the next }, as we've incremented paren_deep.

		break;
	    case '}':
		paren_deep--;

		if ( !recursed && paren_deep < 0 )
		{
		    D( "The JSON dwarves delved too deep: %d!", __LINE__ );
		    free_nvll( rootnvll );
		    return NULL;
		}

		if ( recursed && paren_deep == 0 )
		{
		    D( "Found the bottom of my stack.  Returning at i=%ld.", i );
		    *recursed = i;
		    return rootnvll;
		}

		break;
	    //TODO: Dies on nulls at the moment.  Fix that.
	    default:
		D( "Unhandled character '%c' in json input.  Bailing.\n", json[i] );
		return NULL;
	}
    }

    if ( paren_deep != 0 )
    {
	D( "Parse error: paren_deep is %d (and should be zero).  Bailing.", paren_deep );
	free_nvll( rootnvll );
	return NULL;
    }

    D( "All's well: returning '%p'.", rootnvll );
    D( "Total characters parsed: %ld.", i );

    return rootnvll;
}

void print_nvll( struct dfuse_nv_ll *rootnvll, unsigned long deep )
{
    struct dfuse_nv_ll *thisnvll;
    int i;

    if ( !rootnvll )
    {
	D( "Bailing early; asked to print an empty nvll at deep=%ld.", deep );
	return;
    }

    for ( i = 0; i < deep; i++ ) { printf( "\t" ); }

    printf( "{\n" );

    for ( thisnvll = rootnvll; thisnvll; thisnvll = thisnvll->next )
    {
	if ( thisnvll->name )
	{
	    for ( i = 0; i < deep; i++ ) { printf( "\t" ); }

	    //Blatantly not null-safe, but this is intended as a debugging function.
	    printf( "%s: ", thisnvll->name->string );

	    if ( thisnvll->nvll_value )
	    {
		print_nvll( thisnvll->nvll_value, deep+1 );
	    }
	    else if ( thisnvll->value )
	    {
		//Blatantly not null-safe, but this is intended as a debugging function.
		printf( "\"%s\",\n", thisnvll->value->string );
	    }
	    else
	    {
		printf( "null,\n" );
	    }
	}
    }

    for ( i = 0; i < deep; i++ ) { printf( "\t" ); }

    printf( "}\n" );
}

static int dfuse_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
{
    switch( key )
    {
	case KEY_HELP:
	case KEY_VERSION:
	    return -1;
	    break; //For thoroughness
	case KEY_LAZY_CONNECT:
	    lazy_conn = 1;
	    return 0;
	    break; //Paranoia, it's all the rage this year.
	case KEY_FOREGROUND:
	    if ( fuse_daemonize(1) )
	    {
		printf( "Failed to forestall daemonization.\n" );
		return -1;
	    }
	    return 0;
	    break;
	case KEY_JSON:
	    json = 1;
	    return 0;
	    break;
	default:
	    return 1; //"1" in this case means "not my problem": typically, the mountpoint.  Possibly other gibberish, though.
    }

    return -1; //Now this, on the other hand, is indefensibly paranoid.
}

FILE *debug_fd( void )
{
    if ( cached_debug_fd ) { return cached_debug_fd; }

    if ( !( cached_debug_fd = fopen( "/tmp/fusedebug", "a" ) ) )
    {
	exit(-1);
    }

    return cached_debug_fd;
}

static int dfuse_readlink(const char *path, char *linkbuf, size_t bufsize )
{
    //In the interest of saving ourselves a lot of time, if this is being called,
    //it's a symlink, and if it is, it's always the same one.

    //TAG: NULL_HANDLING

    if ( bufsize <= 0 )
    {
	DFRV(-EINVAL);
    }

    if ( bufsize < strlen("/dev/null") + 1 ) //libc function says strlen(/dev/null), but FUSE API docs say +1.
    {
	DFRV(-ENOMEM);
    }

    strncpy(linkbuf,"/dev/null",bufsize);
    DFRV(0);
}

static int dfuse_getattr(const char *path, struct stat *stbuf)
{
    MYSQL *sql;
    MYSQL_RES *sql_res;
    MYSQL_ROW sql_row;
    int qr;
    char sqlbuf[2000];
    char *clean_path;
    struct string_length *url_path_struct;
    char *url_path;

    if( !path || path[0] == '\0' )
    {
	DFRV(-ENOENT);
    }

    memset(stbuf, 0, sizeof(struct stat));
    if(strcmp(path, "/") == 0) {
	stbuf->st_mode = S_IFDIR | 0755;
	stbuf->st_nlink = 2;
    }
    else {
	stbuf->st_mode = S_IFREG | 0644;
	stbuf->st_nlink = 1;

	if ( !(url_path_struct = urldecode(path+sizeof(char)) ) )
	{
	    DFRV(-ENOMEM); //Not necessarily ENOMEM, but something went wrong, anyway.
	}

	url_path = url_path_struct->string;

	if ( !(sql = dfuse_connect( NULL, NULL, NULL, NULL ) ) )
	{
	    DFUSE_FREE(url_path);
	    DFUSE_FREE(url_path_struct);
	    DFRV(-EIO);
	}

	if ( !( clean_path = DFUSE_MALLOC((url_path_struct->length)*2+1) ) )
	{
	    DFUSE_FREE(url_path);
	    DFUSE_FREE(url_path_struct);
	    DFRV(-ENOMEM);
	}

	mysql_real_escape_string( sql, clean_path, url_path, url_path_struct->length );

	if ( strlen(clean_path) <= 0 )
	{
	    DFUSE_FREE(url_path);
	    DFUSE_FREE(url_path_struct);
	    DFUSE_FREE(clean_path);
	    DFRV(-ENOENT);
	}

	//DONE: mysql_real_escape_string, test for zero-length path
	if ( json )
	{
	    if ( 0 > snprintf( sqlbuf, MAX_SQL_LENGTH, "SELECT %s FROM %s WHERE %s='%s'", options.columns, options.table, options.prikey, clean_path ) )
	    {
		DFUSE_FREE(url_path);
		DFUSE_FREE(url_path_struct);
		DFUSE_FREE(clean_path);
		DFRV(-EIO);
	    }
	}
	else if ( options.timestamp )
	{
	    if ( 0 > snprintf( sqlbuf, MAX_SQL_LENGTH, "SELECT OCTET_LENGTH(%s),%s FROM %s WHERE %s='%s'", options.columns, options.timestamp, options.table, options.prikey, clean_path ) )
	    {
		DFUSE_FREE(url_path);
		DFUSE_FREE(url_path_struct);
		DFUSE_FREE(clean_path);
		DFRV(-EIO);
	    }
	}
	else
	{
	    if ( 0 > snprintf( sqlbuf, MAX_SQL_LENGTH, "SELECT OCTET_LENGTH(%s) FROM %s WHERE %s='%s'", options.columns, options.table, options.prikey, clean_path) )
	    {
		DFUSE_FREE(url_path);
		DFUSE_FREE(url_path_struct);
		DFUSE_FREE(clean_path);
		DFRV(-EIO);
	    }
	}

	qr = mysql_query( sql, sqlbuf );

	switch( qr )
	{
	    case CR_COMMANDS_OUT_OF_SYNC:
	    case CR_SERVER_GONE_ERROR:
	    case CR_SERVER_LOST:
	    case CR_UNKNOWN_ERROR:
	    default:
		DFUSE_FREE(url_path);
		DFUSE_FREE(url_path_struct);
		DFUSE_FREE(clean_path);

		DFRV(-EIO);
	    case 0:
		break;
	}

	if ( !( sql_res = mysql_store_result( sql ) ) )
	{
	    DFUSE_FREE(url_path);
	    DFUSE_FREE(url_path_struct);
	    DFUSE_FREE(clean_path);

	    DFRV(-EIO);
	}

	if ( mysql_num_rows( sql_res ) == 0 )
	{
	    DFUSE_FREE(url_path);
	    DFUSE_FREE(url_path_struct);
	    DFUSE_FREE(clean_path);

	    mysql_free_result( sql_res );

	    DFRV(-ENOENT);
	}
	else if ( mysql_num_rows( sql_res ) != 1 )
	{
	    DFUSE_FREE(url_path);
	    DFUSE_FREE(url_path_struct);
	    DFUSE_FREE(clean_path);

	    mysql_free_result( sql_res );

	    DFRV(-EIO);
	}

	sql_row = mysql_fetch_row( sql_res );	

//	fprintf( debug_fd(), "st_size: %d\n", atoi(sql_row[0]) );

	if ( json )
	{
	    char * jsonified = dfuse_jsonify_row( &sql_row, sql_res, url_path, url_path_struct->length);
	    //Blatant opportunity for caching/optimization.

	    if ( !jsonified )
	    {
		DFUSE_FREE(url_path);
		DFUSE_FREE(url_path_struct);
		DFUSE_FREE(clean_path);

		DFRV(-ENOMEM); //Hard to know for sure, but a likely cause, at least.
	    }

	    D("Got a jsonified string: '%s'.\n", jsonified);

	    D("Looks to be about %ld long.\n", strlen(jsonified));

	    stbuf->st_size = strlen(jsonified);

	    D("It's %ld long.\n", stbuf->st_size);

	    DFUSE_FREE( jsonified );
	}
	else if ( sql_row[0] == NULL ) //This will happen if table[prikey].column is NULL
	{
	    // TAG: NULL_HANDLING
	    stbuf->st_size = strlen("/dev/null")-1;
	
	    if ( stbuf->st_mode & S_IFREG )
	    {
		// I recognize that there are cheaper ways to do this, but I didn't want
		// to have to have a 0xfffffffff or whatever, just in case someone has a
		// freaky set of st_mode flags.
		stbuf->st_mode -= S_IFREG;
	    }
	    stbuf->st_mode |= S_IFLNK;
//	    DFRV(-ENOENT); //This creates an unambiguous representation of NULL (vs "")
//	    stbuf->st_size = 0;
	}
	else
	{
	    stbuf->st_size = atoi(sql_row[0]);
	}

	if ( !json && options.timestamp && sql_row[1])
	{
//	    fprintf( debug_fd(), "st_(x)time: %d\n", atoi(sql_row[1]) );
	    stbuf->st_atime = stbuf->st_mtime = stbuf->st_ctime = atoi(sql_row[1]);
	}

	// TODO: properly support timestamp in json mode
	if ( json && options.timestamp )
	{
	    stbuf->st_atime = stbuf->st_mtime = stbuf->st_ctime = time(NULL);
	}

	DFUSE_FREE(url_path);
	DFUSE_FREE(url_path_struct);
	DFUSE_FREE(clean_path);

	mysql_free_result( sql_res );
    }

//    usleep( 10000 );

    DFRV(0);
}

static int dfuse_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
    return dfuse_getattr(path,stbuf);
}

MYSQL *dfuse_connect( char *host, char *user, char *pass, char *defaultdb )
{
    int use_defaults = 0;
    MYSQL *sql = NULL;

    if ( !host || !user || !pass || !defaultdb )
    {
	use_defaults = 1;
    }

    if ( !use_defaults )
    {
	if ( !( sql = mysql_init( NULL ) ) )
	{
	    return NULL;
	}
	return mysql_real_connect( sql, host, user, pass, defaultdb, 0, NULL, 0 );
    }

    if ( cached_sql && !mysql_ping( cached_sql ) ) //0 = connection is up, so !ping is a good thing
    {
	return cached_sql;
    }

    if ( cached_sql != NULL ) //If we had an old one, kill it cleanly, just in case
    {
	mysql_close( cached_sql );
	cached_sql = NULL;
    }

    if ( !( cached_sql = mysql_init( NULL ) ) )
    {
	return NULL;
    }

    cached_sql = mysql_real_connect( cached_sql, MYSQLSERVER, MYSQLUSER, MYSQLPASS, MYSQLDB, 0, NULL, 0 );

    return cached_sql;
}

static int dfuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
    MYSQL *sql;
    MYSQL_RES *sql_res;
    MYSQL_ROW sql_row;
    int qr;
    char sqlbuf[2000];

    // There's only one directory, and it's "/".
    if(strcmp(path, "/") != 0)
    {
	DFRV(-ENOENT);
    }

    if ( !(sql = dfuse_connect( NULL, NULL, NULL, NULL ) ) )
    {
	DFRV(-EIO);
    }

    if ( 0 > ( snprintf( sqlbuf, MAX_SQL_LENGTH, "SELECT %s FROM %s", options.prikey, options.table ) ) )
    {
	DFRV(-EIO);
    }

    qr = mysql_query( sql, sqlbuf );

    switch( qr )
    {
	case CR_COMMANDS_OUT_OF_SYNC:
	case CR_SERVER_GONE_ERROR:
	case CR_SERVER_LOST:
	case CR_UNKNOWN_ERROR:
	default:
	    DFRV(-EIO);
	case 0:
	    break;
    }

    if ( !( sql_res = mysql_use_result( sql ) ) )
    {
	DFRV(-EIO);
    }

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    while ( ( sql_row = mysql_fetch_row( sql_res ) ) )
    {
	char * ptr;
	if ( (filler(buf, ptr = urlencode(sql_row[0], mysql_fetch_lengths( sql_res )[0]), NULL, 0) ) )
	{
	    //The "filler" func's buffer is full, but it's unclear what the right thing to do is here.
	    //Opt to fail (very) noisily.
	    raise(SIGSEGV);
	}
	DFUSE_FREE(ptr);
    }

    mysql_free_result( sql_res );

    DFRV(0);
}

static int dfuse_open(const char *path, struct fuse_file_info *fi)
{
    MYSQL *sql;
    MYSQL_RES *sql_res;
    int qr;
    char sqlbuf[2000];
    struct string_length *url_path_struct;
    char *url_path, *clean_path;

    D( "Asked to open '%s'.", path );

    // The O_ACCMODE dance is needed because O_RDONLY is 0x0.  @#&$*
//    if((fi->flags & O_ACCMODE) != O_RDONLY)

    if ( !(sql = dfuse_connect( NULL, NULL, NULL, NULL ) ) )
    {
	DFRV(-EIO);
    }

    if ( !path || path[0] == '\0' )
    {
	DFRV(-EIO);
    }

    if ( !( url_path_struct = urldecode(path+sizeof(char)) ) )
    {
	DFRV(-ENOMEM);
    }

    url_path = url_path_struct->string;

    if ( !( clean_path = DFUSE_MALLOC((url_path_struct->length)*2+1) ) )
    {
	DFUSE_FREE(url_path);
	DFUSE_FREE(url_path_struct);
	DFRV(-ENOMEM);
    }

    mysql_real_escape_string( sql, clean_path, url_path, url_path_struct->length );

    if ( strlen(clean_path) <= 0 )
    {
	DFUSE_FREE(url_path);
	DFUSE_FREE(url_path_struct);
	DFUSE_FREE(clean_path);
	DFRV(-ENOENT);
    }

    //The "0 >" test means that the resultant string can be nonsense (cut off due to being
    //longer than MAX_SQL_LENGTH), but that's okay; MySQL will yell at us for that here in
    //a minute.
    if ( 0 > snprintf( sqlbuf, MAX_SQL_LENGTH, "SELECT %s FROM %s WHERE %s='%s'", options.prikey, options.table, options.prikey, clean_path) )
    {
	DFUSE_FREE(url_path);
	DFUSE_FREE(url_path_struct);
	DFUSE_FREE(clean_path);
	DFRV(-EIO);
    }

    DFUSE_FREE(url_path);
    DFUSE_FREE(url_path_struct);
    DFUSE_FREE(clean_path);

    D( "Running SQL: '%s'.", sqlbuf );

    qr = mysql_query( sql, sqlbuf );

    switch( qr )
    {
	case CR_COMMANDS_OUT_OF_SYNC:
	    DFRV(-EDEADLK);
	case CR_SERVER_GONE_ERROR:
	case CR_SERVER_LOST:
	case CR_UNKNOWN_ERROR:
	default:
	    DFRV(-EIO);
	case 0:
	    break;
    }

    if ( !( sql_res = mysql_store_result( sql ) ) )
    {
	DFRV(-EIO);
    }

    if ( mysql_num_rows( sql_res ) == 0 )
    {
	DFRV(-ENOENT);
    }
    else if ( mysql_num_rows( sql_res ) != 1 )
    {
	DFRV(-EIO);
    }

    mysql_free_result( sql_res );

    DFRV(0);
}

char * forge_update( struct dfuse_nv_ll * rootnvll )
{
    struct dfuse_nv_ll * thisnvll;
    char *rv, clean_name, clean_val;

    rv = malloc(16384); //TODO: Blatant security hole
    rv[0] = '\0';

    for ( thisnvll = rootnvll; thisnvll; thisnvll = thisnvll->next )
    {
	if ( thisnvll->nvll_value )
	{
	    if ( rv[0] == '\0' )
	    {
		sprintf( rv, "%s", forge_update(thisnvll->nvll_value) ); //No need to %s%s here; rv[0] is null!
	    }
	    else
	    {
		D( "This should never happen with DFuse-generated JSON: got deeply-nested JSON with rv so far='%s'.", rv );
		sprintf( rv, "%s, %s", rv, forge_update(thisnvll->nvll_value) );
	    }
	}
	else if ( thisnvll->name && thisnvll->value )
	{
	    if ( rv[0] == '\0' )
	    {
		//TODO: blatantly not NULL-safe.
		sprintf( rv, "`%s`='%s'", thisnvll->name->string, thisnvll->value->string );
	    }
	    else
	    {
		//TODO: blatantly not NULL-safe.
		sprintf( rv, "%s, `%s`='%s'", rv, thisnvll->name->string, thisnvll->value->string );
	    }
	}
    }

    return rv;
}

static int dfuse_flush(const char *path, struct fuse_file_info *fi)
{
    return 0;
}

static int dfuse_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    return 0;
}

static int dfuse_truncate(const char *path, off_t offset)
{
    return 0;
}

static int dfuse_write(const char *path, const char *buf, size_t size, off_t offset,
			struct fuse_file_info *fi)
{
    MYSQL *sql;
    int qr;
    char sqlbuf[2000];
    struct string_length *url_path_struct;
    char *url_path, *clean_path;
    struct dfuse_nv_ll *rootnvll = NULL;

    //We don't do any buffering quite yet, so write it all at once or not at all.
    if ( size <= 0 || offset != 0 )
    {
	DFRV(-EFAULT);
    }

    //TODO: Refactor; this is literally a C&P from dfuse_read
    if ( !(sql = dfuse_connect( NULL, NULL, NULL, NULL ) ) )
    {
	DFRV(-EIO);
    }

    if ( !path || path[0] == '\0' )
    {
	DFRV(-ENOENT);
    }

    if ( !(url_path_struct = urldecode(path+sizeof(char)) ) )
    {
	DFRV(-ENOMEM);
    }

    url_path = url_path_struct->string;

    if ( !( clean_path = DFUSE_MALLOC((url_path_struct->length)*2+1) ) )
    {
	DFUSE_FREE(url_path);
	DFUSE_FREE(url_path_struct);
	DFRV(-ENOMEM);
    }

    mysql_real_escape_string( sql, clean_path, url_path, url_path_struct->length );

    if ( strlen(clean_path) <= 0 )
    {
	DFUSE_FREE(url_path);
	DFUSE_FREE(url_path_struct);
	DFUSE_FREE(clean_path);
	DFRV(-ENOENT);
    }

    if ( 0 > snprintf( sqlbuf, MAX_SQL_LENGTH, "SELECT %s FROM %s WHERE %s='%s'", options.columns, options.table, options.prikey, clean_path) )
    {
	DFUSE_FREE(url_path);
	DFUSE_FREE(url_path_struct);
	DFUSE_FREE(clean_path);
	DFRV(-EIO);
    }

    D( "Querying: '%s'.\n", sqlbuf );

    qr = mysql_query( sql, sqlbuf );

    switch( qr )
    {
	case CR_COMMANDS_OUT_OF_SYNC:
	case CR_SERVER_GONE_ERROR:
	case CR_SERVER_LOST:
	case CR_UNKNOWN_ERROR:
	default:
	    DFUSE_FREE(url_path);
	    DFUSE_FREE(url_path_struct);
	    DFUSE_FREE(clean_path);

	    DFRV(-EIO);
	case 0:
	    break;
    }

    if ( !( rootnvll = dfuse_parse_json( buf, size, NULL ) ) )
    {
	DFUSE_FREE(url_path);
	DFUSE_FREE(url_path_struct);
	DFUSE_FREE(clean_path);

	DFRV(-EIO);
    }

    D("Got an UPDATE: UPDATE `%s`", clean_path);
    D(" SET %s.\n", forge_update(rootnvll));

    return size;
}

static int dfuse_read(const char *path, char *buf, size_t size, off_t offset,
			struct fuse_file_info *fi)
{
    size_t len;
//    (void) fi;
    MYSQL *sql;
    MYSQL_RES *sql_res;
    MYSQL_ROW sql_row;
    int qr;
    char sqlbuf[2000];
    struct string_length *url_path_struct;
    char *url_path, *clean_path;
    char *rv;

    if ( !(sql = dfuse_connect( NULL, NULL, NULL, NULL ) ) )
    {
	DFRV(-EIO);
    }

    if ( !path || path[0] == '\0' )
    {
	DFRV(-ENOENT);
    }

    if ( !(url_path_struct = urldecode(path+sizeof(char)) ) )
    {
	DFRV(-ENOMEM);
    }

    url_path = url_path_struct->string;

    if ( !( clean_path = DFUSE_MALLOC((url_path_struct->length)*2+1) ) )
    {
	DFUSE_FREE(url_path);
	DFUSE_FREE(url_path_struct);
	DFRV(-ENOMEM);
    }

    mysql_real_escape_string( sql, clean_path, url_path, url_path_struct->length );

    if ( strlen(clean_path) <= 0 )
    {
	DFUSE_FREE(url_path);
	DFUSE_FREE(url_path_struct);
	DFUSE_FREE(clean_path);
	DFRV(-ENOENT);
    }

    if ( 0 > snprintf( sqlbuf, MAX_SQL_LENGTH, "SELECT %s FROM %s WHERE %s='%s'", options.columns, options.table, options.prikey, clean_path) )
    {
	DFUSE_FREE(url_path);
	DFUSE_FREE(url_path_struct);
	DFUSE_FREE(clean_path);
	DFRV(-EIO);
    }

    DFUSE_FREE(clean_path);

    qr = mysql_query( sql, sqlbuf );

    switch( qr )
    {
	case CR_COMMANDS_OUT_OF_SYNC:
	case CR_SERVER_GONE_ERROR:
	case CR_SERVER_LOST:
	case CR_UNKNOWN_ERROR:
	default:
	    DFUSE_FREE(url_path);
	    DFUSE_FREE(url_path_struct);

	    DFRV(-EIO);
	case 0:
	    break;
    }

    if ( !( sql_res = mysql_store_result( sql ) ) )
    {
	DFUSE_FREE(url_path);
	DFUSE_FREE(url_path_struct);

	DFRV(-EIO);
    }

    if ( mysql_num_rows( sql_res ) == 0 )
    {
	DFUSE_FREE(url_path);
	DFUSE_FREE(url_path_struct);

	DFRV(-ENOENT);
    }

    if ( mysql_num_rows( sql_res ) != 1 )
    {
	DFUSE_FREE(url_path);
	DFUSE_FREE(url_path_struct);

	DFRV(-EIO);
    }

    sql_row = mysql_fetch_row( sql_res );

    if ( json )
    {
	D("url_path: '%s'\n",url_path);
	rv = dfuse_jsonify_row( &sql_row, sql_res, url_path, url_path_struct->length );
    }
    else
    {
	if ( sql_row[0] == NULL )
	{
	    DFUSE_FREE(url_path);
	    DFUSE_FREE(url_path_struct);
	    mysql_free_result( sql_res );

	    DFRV(-EINVAL);		// TAG: NULL_HANDLING
	}

	rv = sql_row[0];
    }

    DFUSE_FREE(url_path);
    DFUSE_FREE(url_path_struct);

    if ( !rv || ( len = strlen(rv) ) < 0 )
    {
	mysql_free_result( sql_res );

	DFRV(-ENOENT);
    }

    if (offset < len)
    {
	if (offset + size > len)
	{
	    size = len - offset;
	}
	memcpy(buf, rv + offset, size);
    }
    else
    {
	size = 0;
    }

    if ( json )
    {
	DFUSE_FREE( rv );
    }

    mysql_free_result( sql_res );

    DFRV(size);
}

static struct fuse_operations dfuse_oper = {
    .getattr = dfuse_getattr,
    .fgetattr = dfuse_fgetattr,
    .readdir = dfuse_readdir,
    .open = dfuse_open,
    .read = dfuse_read,
    .write = dfuse_write,
    .flush = dfuse_flush,
    .create = dfuse_create,
    .truncate = dfuse_truncate,
    .readlink = dfuse_readlink,
};

int main(int argc, char *argv[])
{
    int rv = -1;
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
#ifdef ESCAPE_ARGS
    char *clean_table, *clean_prikey, *clean_columns;
    MYSQL *sql;
#endif

#if 0
		/* { "foo": { "bar": "baz", "boo": "boz" } } */
    char * foo = "{ \"foo\": { \"bar&x36;\": \"&x34;baz\", \"&x35;boo&x33;\": \"bo&x32;z\" } }";
//    char * foo = "{\n     \"firstName\": \"John\",\n     \"lastName\": \"Smith\",\n     \"age\": \"&x32;5\",\n     \"address\":\n     {\n         \"streetAddress\": \"21 2nd Street\",\n         \"city\": \"New York\",\n         \"state\": \"NY\",\n         \"postalCode\": \"10021\"\n     },\n     \"phoneNumber\":\n     {\n         \"home\": {\n           \"type\": \"home\",\n           \"number\": \"212 555-1234\"\n         },\n         \"fax\": {\n           \"type\": \"fax\",\n           \"number\": \"646 555-4567\"\n         }\n     }\n }\n";
    struct dfuse_nv_ll * somenvll;

    somenvll = dfuse_parse_json( foo, NULL );

    print_nvll( somenvll, 0 );

    exit( 0 );
#endif


//    printf( "Starting...\n" );

    /* clear structure that holds our options */
    memset(&options, 0, sizeof(struct options));

    if (fuse_opt_parse(&args, &options, dfuse_opts, dfuse_opt_proc))
    {
	usage(argv);
//	printf( "Error parsing options.\n" );
	/** error parsing options, or -h/--help */
	return -1;
    }

    if ( !options.username || !options.password || !options.hostname || !options.database
	|| !options.table || !options.prikey || !options.columns )
    {
	printf( "Undefined critical variable.\n" );

	printf( "You supplied: '%s', '%s', '%s', '%s', '%s', '%s', '%s'.\n",
	  options.username, options.password, options.hostname, options.database,
	  options.table, options.prikey, options.columns );
	usage(argv);

	return -1;
    }

    if ( !strlen(options.username) || !strlen(options.hostname) || !strlen(options.database) )
    {
	printf( "Invalid option set specified: you must declare a username, password, hostname, and database.\n" );
	usage(argv);

	printf( "You specified: '%s', '%s', '%s', '%s'.\n", options.username, options.password, options.hostname, options.database );
	return -1;
    }

#ifdef ESCAPE_ARGS
    if ( !( clean_table = DFUSE_MALLOC(strlen(options.table)*2+1) ) )
    {
	printf( "Unable to allocate memory for clean_table.\n" );

	return -1;
    }

    if ( !( clean_prikey = DFUSE_MALLOC(strlen(options.prikey)*2+1) ) )
    {
	printf( "Unable to allocate memory for clean_prikey.\n" );

	return -1;
    }

    if ( !( clean_columns = DFUSE_MALLOC(strlen(options.columns)*2+1) ) )
    {
	printf( "Unable to allocate memory for clean_columns.\n" );

	return -1;
    }

    if ( !( sql = dfuse_connect( NULL, NULL, NULL, NULL ) ) )
    {
	printf( "Unable to form connection to MySQL: '%s'.\n", mysql_error( sql ) );

	return -1;
    }

    mysql_real_escape_string( sql, clean_table, options.table, strlen(options.table) );
    mysql_real_escape_string( sql, clean_prikey, options.prikey, strlen(options.prikey) );
    mysql_real_escape_string( sql, clean_columns, options.columns, strlen(options.columns) );

    DFUSE_FREE( options.table );
    DFUSE_FREE( options.prikey );
    DFUSE_FREE( options.columns );

    options.table = clean_table;
    options.prikey = clean_prikey;
    options.columns = clean_columns;
#endif

//    printf( "'%s': %d\n", options.table, strlen(options.table) );
//    printf( "'%s': %d\n", options.prikey, strlen(options.prikey) );
//    printf( "'%s': %d\n", options.columns, strlen(options.columns) );

    if ( !strlen(options.table) || !strlen(options.prikey) || !strlen(options.columns) )
    {
	printf( "Invalid option set specified: you must declare a non-zero-length table, primary key(s), and column(s).\n" );
	usage(argv);

	printf( "You specified: '%s', '%s', '%s'.\n", options.table, options.prikey, options.columns );
	return -1;
    }

    //Arguably, we should try to connect to the DB here, just to ensure that we can do so before we daemonize ourselves away.
    if ( !dfuse_connect( NULL, NULL, NULL, NULL ) )
    {
	printf( "Failed to connect: MySQL server said, '%s'.\n", mysql_error( NULL ) );
	return -1;
    }

    rv = fuse_main(args.argc, args.argv, &dfuse_oper);

    if (rv)
    {
	printf("\n");
    }

    /** free arguments */
    fuse_opt_free_args(&args);

    return rv;
}

void usage( char **argv )
{
    printf( "Usage: %s <options> <mountpoint>\n"
	"  -u: Username [MANDATORY]\n"
	"  -p: Password [MANDATORY]\n"
	"  -H: Hostname [MANDATORY]\n"
	"  -D: DB Name  [MANDATORY]\n"
	"  -t: Table    [MANDATORY]\n"
	"  -P: Prim. Key(s) [MANDATORY]\n"
	"  -c: Column(s) [MANDATORY]\n"
	"  -T: Timestamp Column (Try 'UNIX_TIMESTAMP()' if your RCS is braindead.)\n"
	"      At the moment, defaults to NOW() in --json mode when specified,\n"
	"      regardless of what argument you pass to it.\n"
	"  --lazy-connect: Connect to DB only when needed, disconnect afterward.\n"
	"                  By default, a connection is opened and kept open for\n"
	"                  as long as the server will let us.  In lazy mode, we\n"
	"                  actively close our connection when we're done with it.\n"
	"                  Bad for performance, great for max_connections.\n"
	"  --json: Output in JSON format (try combining with -c '*').\n"
//	Foreground doesn't seem to work properly at the moment; we'll leave it active,
//	but undocumented, in case I'm just misunderstanding what it's doing.
//	"  -f, --foreground: Don't daemonize (handy for debugging).\n"
	, argv[0] );
}
