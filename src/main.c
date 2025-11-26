#include <ctype.h>
#include <errno.h>
#include <ncurses.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_ENTRIES 1024
#define MAX_DESCRIPTION 200
#define MAX_USER 128
#define MAX_PASSWORD 256
#define MAX_URL 256
#define MAX_TAGS 1000 /* up to 10 tags x 100 chars, comma separated */
#define MAX_COMMENT 300
#define MAX_STATUS 16
#define MAX_DATE 64
#define MAX_LINE 2048

#define FRAME_PAIR 1
#define TITLE_PAIR 2
#define BODY_PAIR 3
#define ERROR_PAIR 4
#define STATUS_OFF_PAIR 5

#define FRAME_COLOR_ID 8
#define TITLE_COLOR_ID 9
#define BODY_COLOR_ID 10
#define ERROR_COLOR_ID 11
#define STATUS_OFF_COLOR_ID 12
#define BODY_START_ROW 3
#define MAX_PATH_LEN 512

typedef struct {
    int id;
    char description[MAX_DESCRIPTION + 1];
    char user[MAX_USER + 1];
    char password[MAX_PASSWORD + 1];
    char url[MAX_URL + 1];
    char comment[MAX_COMMENT + 1];
    char tags[MAX_TAGS + 1];
    char createdate[MAX_DATE + 1];
    char updatedate[MAX_DATE + 1];
    char status[MAX_STATUS + 1];
} Entry;

typedef struct {
    Entry items[MAX_ENTRIES];
    size_t count;
    int next_id;
} Database;

static const char *HEADER = "id,description,user,password,url,comment,tags,createdate,updatedate,status";
static const char *PROGRAM_NAME = "vaultdb";
static const char *PROGRAM_VERSION = "0.1.0";
static const char *PROGRAM_AUTHOR = "Robert Tulke <rt@debian.sh>";
static const char *PROGRAM_LICENSE = "MIT";

static const char *DB_STATUS_OFFLINE = "locked";
static const char *DB_STATUS_ONLINE = "unlocked";
static const char *db_status = "locked";
static char db_path[MAX_PATH_LEN] = "vault.db";

static void generate_password(char *out, size_t max_len, int length, int mode);

/* Utility helpers */
static int strcasecmp_portable(const char *a, const char *b) {
    while (*a && *b) {
        int da = tolower((unsigned char)*a);
        int db = tolower((unsigned char)*b);
        if (da != db) return da - db;
        a++;
        b++;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

static bool file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static void ensure_dir_for_path(const char *path) {
    char tmp[MAX_PATH_LEN];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    char *slash = strrchr(tmp, '/');
    if (!slash) return;
    *slash = '\0';
    if (strlen(tmp) == 0) return;
    mkdir(tmp, 0700);
}

static void xor_buffer(unsigned char *data, size_t len, const char *key) {
    size_t key_len = strlen(key);
    if (key_len == 0) return;
    for (size_t i = 0; i < len; ++i) {
        data[i] ^= (unsigned char)key[i % key_len];
    }
}

static void now_string(char *buf, size_t size) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    strftime(buf, size, "%d.%m.%Y %H:%M:%S", tm_info);
}

static bool append_text(char **buf, size_t *blen, size_t *bcap, const char *text) {
    size_t tlen = strlen(text);
    if (*blen + tlen + 1 >= *bcap) {
        size_t new_cap = (*bcap) * 2 + tlen + 1;
        char *tmp = (char *)realloc(*buf, new_cap);
        if (!tmp) return false;
        *buf = tmp;
        *bcap = new_cap;
    }
    memcpy(*buf + *blen, text, tlen);
    *blen += tlen;
    (*buf)[*blen] = '\0';
    return true;
}

/* Colors and UI */
static void init_colors(void) {
    start_color();
    use_default_colors();
    short frame_fg = COLOR_CYAN;
    short title_fg = COLOR_YELLOW;
    /* Use default fg to respect light/dark terminal themes */
    short body_fg = -1;
    short error_fg = COLOR_RED;
    short status_off_fg = COLOR_BLACK;
    if (can_change_color()) {
        init_color(FRAME_COLOR_ID, 314, 314, 470); /* rgb(80,80,120) */
        init_color(TITLE_COLOR_ID, 953, 784, 420); /* rgb(243,200,107) */
        init_color(BODY_COLOR_ID, 910, 863, 769);  /* rgb(232,220,196) */
        init_color(ERROR_COLOR_ID, 200, 804, 874); /* rgb(51,205,223) */
        init_color(STATUS_OFF_COLOR_ID, 251, 251, 251); /* rgb(64,64,64) */
        frame_fg = FRAME_COLOR_ID;
        title_fg = TITLE_COLOR_ID;
        body_fg = BODY_COLOR_ID;
        error_fg = ERROR_COLOR_ID;
        status_off_fg = STATUS_OFF_COLOR_ID;
    }
    init_pair(FRAME_PAIR, frame_fg, -1);
    init_pair(TITLE_PAIR, title_fg, -1);
    init_pair(BODY_PAIR, body_fg, -1);
    init_pair(ERROR_PAIR, error_fg, -1);
    init_pair(STATUS_OFF_PAIR, status_off_fg, -1);
}

static void ui_draw_header(const char *status) {
    move(0, 0);
    clrtoeol();
    attron(COLOR_PAIR(BODY_PAIR));
    printw("db status: ");
    attroff(COLOR_PAIR(BODY_PAIR));
    if (status && strcmp(status, DB_STATUS_ONLINE) == 0) {
        attron(COLOR_PAIR(ERROR_PAIR));
        printw("%s", status);
        attroff(COLOR_PAIR(ERROR_PAIR));
    } else {
        attron(COLOR_PAIR(STATUS_OFF_PAIR));
        printw("%s", status ? status : DB_STATUS_OFFLINE);
        attroff(COLOR_PAIR(STATUS_OFF_PAIR));
    }

    attron(COLOR_PAIR(FRAME_PAIR));
    mvprintw(0, (COLS - (int)strlen(PROGRAM_NAME)) / 2, "%s", PROGRAM_NAME);
    attroff(COLOR_PAIR(FRAME_PAIR));
    /* spacer lines */
    for (int r = 1; r < BODY_START_ROW; ++r) {
        move(r, 0);
        clrtoeol();
    }
    refresh();
}

static void ui_init(void) {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(1);
    init_colors();
}

static void ui_shutdown(void) {
    endwin();
}

static void ui_draw_divider(void) {
    int row = LINES - 2;
    move(row, 0);
    attron(COLOR_PAIR(FRAME_PAIR));
    hline(ACS_HLINE, COLS);
    attroff(COLOR_PAIR(FRAME_PAIR));
    refresh();
}

static void ui_clear_body(void) {
    move(BODY_START_ROW, 0);
    for (int r = BODY_START_ROW; r < LINES - 2; ++r) {
        move(r, 0);
        clrtoeol();
    }
    attrset(COLOR_PAIR(BODY_PAIR));
}

static void ui_center_box(const char *title, const char *body) {
    ui_clear_body();

    char copy[MAX_LINE];
    int body_lines = 0;
    int max_len = 0;
    const int max_store = 32;
    char *lines[max_store];
    if (body) {
        strncpy(copy, body, sizeof(copy) - 1);
        copy[sizeof(copy) - 1] = '\0';
        char *line = strtok(copy, "\n");
        while (line && body_lines < max_store) {
            lines[body_lines++] = line;
            int len = (int)strlen(line);
            if (len > max_len) max_len = len;
            line = strtok(NULL, "\n");
        }
    }

    /* Extra column to keep one leading space between border and text */
    int width = max_len + 5;
    if (title && (int)strlen(title) + 4 > width) width = (int)strlen(title) + 4;
    if (width < 30) width = 30;
    if (width > COLS - 2) width = COLS - 2;

    int height = (title ? 3 : 2) + body_lines + 2;
    if (height < 6) height = 6;
    if (height > LINES - 2) height = LINES - 2;

    int starty = (LINES - height) / 2;
    int startx = (COLS - width) / 2;
    if (starty < 0) starty = 0;
    if (startx < 0) startx = 0;

    attron(COLOR_PAIR(FRAME_PAIR));
    mvaddch(starty, startx, ACS_ULCORNER);
    mvhline(starty, startx + 1, ACS_HLINE, width - 2);
    mvaddch(starty, startx + width - 1, ACS_URCORNER);
    for (int y = 1; y < height - 1; ++y) {
        mvaddch(starty + y, startx, ACS_VLINE);
        mvaddch(starty + y, startx + width - 1, ACS_VLINE);
    }
    mvaddch(starty + height - 1, startx, ACS_LLCORNER);
    mvhline(starty + height - 1, startx + 1, ACS_HLINE, width - 2);
    mvaddch(starty + height - 1, startx + width - 1, ACS_LRCORNER);
    attroff(COLOR_PAIR(FRAME_PAIR));

    if (title) {
        attron(COLOR_PAIR(TITLE_PAIR));
        int len = (int)strlen(title);
        int tx = startx + (width - len) / 2;
        if (tx < startx + 1) tx = startx + 1;
        mvprintw(starty + 1, tx, "%s", title);
        attroff(COLOR_PAIR(TITLE_PAIR));
    }
    attron(COLOR_PAIR(BODY_PAIR));
    int y = title ? 3 : 2;
    int inner_text = width - 4; /* leave 1 space each side */
    for (int i = 0; i < body_lines && y < height - 2; ++i) {
        int printable = inner_text - 1; /* leading space inside box */
        if (printable < 0) printable = 0;
        mvprintw(starty + y, startx + 2, " %-*.*s", printable, printable, lines[i]);
        y++;
    }
    /* ensure one blank line before footer */
    int footer_y = starty + height - 2;
    int blank_y = footer_y - 1;
    if (blank_y >= starty + 2) {
        mvprintw(blank_y, startx + 2, "%-*s", inner_text, "");
    }
    /* footer with version bottom-right inside box, leaving 1 space from border */
    int footer_len = (int)(strlen(PROGRAM_NAME) + strlen(PROGRAM_VERSION) + 3);
    int footer_x = startx + width - 2 - 1 - footer_len;
    if (footer_x < startx + 2) footer_x = startx + 2;
    mvprintw(footer_y, footer_x, "%s v%s", PROGRAM_NAME, PROGRAM_VERSION);
    attroff(COLOR_PAIR(BODY_PAIR));

    ui_draw_divider();
    move(LINES - 1, 0);
    clrtoeol();
    refresh();
}

static void wait_with_input_preserved(int ms) {
    nodelay(stdscr, TRUE);
    int elapsed = 0;
    while (elapsed < ms) {
        int ch = getch();
        if (ch != ERR) {
            ungetch(ch);
            break;
        }
        napms(50);
        elapsed += 50;
    }
    nodelay(stdscr, FALSE);
}

static void ui_show_message(const char *title, const char *body, int wait_ms, bool clear_after) {
    ui_center_box(title, body);
    if (wait_ms > 0) wait_with_input_preserved(wait_ms);
    if (clear_after) {
        ui_clear_body();
        refresh();
    }
}

static void print_error_line(const char *msg) {
    attron(COLOR_PAIR(ERROR_PAIR));
    printw("%s\n", msg);
    attroff(COLOR_PAIR(ERROR_PAIR));
    refresh();
}

/* Input helpers */
static bool read_line(char *buffer, size_t size) {
    size_t idx = 0;
    attrset(COLOR_PAIR(BODY_PAIR));
    noecho();
    keypad(stdscr, TRUE);
    while (1) {
        int ch = getch();
        if (ch == ERR) {
            buffer[0] = '\0';
            return false;
        }
        if (ch == 4) { /* Ctrl+D */
            buffer[0] = '\0';
            return false;
        }
        if (ch == '\n' || ch == '\r') {
            buffer[idx] = '\0';
            return true;
        }
        if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
            if (idx > 0) {
                idx--;
                int y, x;
                getyx(stdscr, y, x);
                if (x > 0) {
                    move(y, x - 1);
                    addch(' ');
                    move(y, x - 1);
                    refresh();
                }
            }
            continue;
        }
        if (!isprint(ch)) continue;
        if (idx + 1 >= size) continue;
        buffer[idx++] = (char)ch;
        addch((ch == '\t') ? ' ' : ch);
        refresh();
    }
}

static bool read_password_obfuscated(char *buffer, size_t size) {
    int starty, startx;
    getyx(stdscr, starty, startx);
    size_t idx = 0;
    int star_counts[1024] = {0};
    int star_total = 0;

    noecho();
    keypad(stdscr, TRUE);
    while (1) {
        int ch = getch();
        if (ch == '\n' || ch == '\r') {
            buffer[idx] = '\0';
            return true;
        }
        if (ch == 4) { /* Ctrl+D */
            buffer[0] = '\0';
            return false;
        }
        if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
            if (idx > 0) {
                idx--;
                int stars = star_counts[idx];
                star_total -= stars;
                move(starty, startx + star_total);
                for (int i = 0; i < stars; ++i) addch(' ');
                move(starty, startx + star_total);
                refresh();
            }
            continue;
        }
        if (idx + 1 >= size) continue;
        int stars = (rand() % 3) + 1;
        star_counts[idx] = stars;
        buffer[idx++] = (char)ch;
        for (int i = 0; i < stars; ++i) addch('*');
        star_total += stars;
        refresh();
    }
}

static bool prompt_command(const char *label, char *buffer, size_t size) {
    (void)label;
    ui_draw_divider();
    move(LINES - 1, 0);
    clrtoeol();
    attron(COLOR_PAIR(FRAME_PAIR));
    printw("vault");
    attroff(COLOR_PAIR(FRAME_PAIR));
    attron(COLOR_PAIR(TITLE_PAIR));
    printw(">");
    attroff(COLOR_PAIR(TITLE_PAIR));
    printw(" ");
    refresh();
    return read_line(buffer, size);
}

static bool prompt_password(const char *label, char *buffer, size_t size) {
    ui_draw_divider();
    move(LINES - 1, 0);
    clrtoeol();
    if (label) {
        attron(COLOR_PAIR(BODY_PAIR));
        printw("%s", label);
        attroff(COLOR_PAIR(BODY_PAIR));
    }
    refresh();
    return read_password_obfuscated(buffer, size);
}

/* CSV helpers */
static void csv_escape(const char *src, char *dest, size_t dest_size) {
    size_t j = 0;
    dest[j++] = '"';
    for (size_t i = 0; src[i] && j + 2 < dest_size; ++i) {
        if (src[i] == '"' || src[i] == '\\') {
            if (j + 2 >= dest_size) break;
            dest[j++] = '\\';
        }
        dest[j++] = src[i];
    }
    dest[j++] = '"';
    dest[j] = '\0';
}

/* Persistence */
static bool save_database(const Database *db, const char *path, const char *master) {
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to open DB for writing: %s\n", strerror(errno));
        return false;
    }

    size_t cap = 8192;
    size_t len = 0;
    char *plain = (char *)malloc(cap);
    if (!plain) {
        fclose(fp);
        return false;
    }

    char field[MAX_LINE];
    char row[MAX_LINE * 2];

    if (!append_text(&plain, &len, &cap, HEADER) || !append_text(&plain, &len, &cap, "\n")) {
        free(plain);
        fclose(fp);
        return false;
    }

    for (size_t i = 0; i < db->count; ++i) {
        const Entry *e = &db->items[i];
        row[0] = '\0';
        char idbuf[32];
        snprintf(idbuf, sizeof(idbuf), "%d,", e->id);
        strncat(row, idbuf, sizeof(row) - strlen(row) - 1);

        csv_escape(e->description, field, sizeof(field));
        strncat(row, field, sizeof(row) - strlen(row) - 1);
        strncat(row, ",", sizeof(row) - strlen(row) - 1);

        csv_escape(e->user, field, sizeof(field));
        strncat(row, field, sizeof(row) - strlen(row) - 1);
        strncat(row, ",", sizeof(row) - strlen(row) - 1);

        csv_escape(e->password, field, sizeof(field));
        strncat(row, field, sizeof(row) - strlen(row) - 1);
        strncat(row, ",", sizeof(row) - strlen(row) - 1);

        csv_escape(e->url, field, sizeof(field));
        strncat(row, field, sizeof(row) - strlen(row) - 1);
        strncat(row, ",", sizeof(row) - strlen(row) - 1);

        csv_escape(e->comment, field, sizeof(field));
        strncat(row, field, sizeof(row) - strlen(row) - 1);
        strncat(row, ",", sizeof(row) - strlen(row) - 1);

        csv_escape(e->tags, field, sizeof(field));
        strncat(row, field, sizeof(row) - strlen(row) - 1);
        strncat(row, ",", sizeof(row) - strlen(row) - 1);

        csv_escape(e->createdate, field, sizeof(field));
        strncat(row, field, sizeof(row) - strlen(row) - 1);
        strncat(row, ",", sizeof(row) - strlen(row) - 1);

        csv_escape(e->updatedate, field, sizeof(field));
        strncat(row, field, sizeof(row) - strlen(row) - 1);
        strncat(row, ",", sizeof(row) - strlen(row) - 1);

        csv_escape(e->status, field, sizeof(field));
        strncat(row, field, sizeof(row) - strlen(row) - 1);
        strncat(row, "\n", sizeof(row) - strlen(row) - 1);

        if (!append_text(&plain, &len, &cap, row)) {
            free(plain);
            fclose(fp);
            return false;
        }
    }

    xor_buffer((unsigned char *)plain, len, master);
    fwrite(plain, 1, len, fp);

    free(plain);
    fclose(fp);
    return true;
}

static bool parse_line_to_entry(const char *line, Entry *e) {
    char fields[10][MAX_LINE] = {{0}};
    int field_idx = 0;
    bool in_quote = false;
    bool escape = false;
    size_t pos = 0;

    for (size_t i = 0; line[i] != '\0'; ++i) {
        char ch = line[i];
        if (escape) {
            if (pos + 1 < sizeof(fields[0])) fields[field_idx][pos++] = ch;
            escape = false;
            continue;
        }
        if (ch == '\\' && in_quote) {
            escape = true;
            continue;
        }
        if (ch == '"') {
            in_quote = !in_quote;
            continue;
        }
        if (ch == ',' && !in_quote) {
            fields[field_idx][pos] = '\0';
            field_idx++;
            pos = 0;
            if (field_idx >= 10) break;
            continue;
        }
        if (pos + 1 < sizeof(fields[0])) fields[field_idx][pos++] = ch;
    }
    fields[field_idx][pos] = '\0';
    field_idx++;
    if (field_idx != 10) return false;

    e->id = atoi(fields[0]);
    strncpy(e->description, fields[1], sizeof(e->description) - 1);
    strncpy(e->user, fields[2], sizeof(e->user) - 1);
    strncpy(e->password, fields[3], sizeof(e->password) - 1);
    strncpy(e->url, fields[4], sizeof(e->url) - 1);
    strncpy(e->comment, fields[5], sizeof(e->comment) - 1);
    strncpy(e->tags, fields[6], sizeof(e->tags) - 1);
    strncpy(e->createdate, fields[7], sizeof(e->createdate) - 1);
    strncpy(e->updatedate, fields[8], sizeof(e->updatedate) - 1);
    strncpy(e->status, fields[9], sizeof(e->status) - 1);
    return true;
}

static bool load_database(Database *db, const char *path, const char *master) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (len <= 0 || len > 10 * 1024 * 1024) {
        fclose(fp);
        return false;
    }
    char *buffer = (char *)malloc((size_t)len + 1);
    if (!buffer) {
        fclose(fp);
        return false;
    }
    fread(buffer, 1, (size_t)len, fp);
    buffer[len] = '\0';
    fclose(fp);

    xor_buffer((unsigned char *)buffer, (size_t)len, master);

    char *saveptr;
    char *line = strtok_r(buffer, "\n", &saveptr);
    if (!line || strcmp(line, HEADER) != 0) {
        free(buffer);
        return false;
    }
    db->count = 0;
    db->next_id = 1;
    while ((line = strtok_r(NULL, "\n", &saveptr))) {
        if (db->count >= MAX_ENTRIES) break;
        if (strlen(line) == 0) continue;
        if (parse_line_to_entry(line, &db->items[db->count])) {
            if (db->items[db->count].id >= db->next_id) {
                db->next_id = db->items[db->count].id + 1;
            }
            db->count++;
        }
    }
    free(buffer);
    return true;
}

/* Filtering helpers */
static bool matches_tag(const char *tags, const char *needle) {
    char tmp[MAX_TAGS + 1];
    strncpy(tmp, tags, sizeof(tmp));
    tmp[sizeof(tmp) - 1] = '\0';
    char *token = strtok(tmp, ",");
    while (token) {
        while (*token && isspace((unsigned char)*token)) token++;
        if (strcasecmp_portable(token, needle) == 0) return true;
        token = strtok(NULL, ",");
    }
    return false;
}

static bool contains_case_insensitive(const char *haystack, const char *needle) {
    if (!needle || !haystack) return false;
    size_t nlen = strlen(needle);
    size_t hlen = strlen(haystack);
    for (size_t i = 0; i + nlen <= hlen; ++i) {
        bool match = true;
        for (size_t j = 0; j < nlen; ++j) {
            if (tolower((unsigned char)haystack[i + j]) != tolower((unsigned char)needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

/* Display */
static void print_separator(void) {
    int y, x;
    getyx(stdscr, y, x);
    move(y, 0);
    attron(COLOR_PAIR(FRAME_PAIR));
    hline(ACS_HLINE, COLS);
    attroff(COLOR_PAIR(FRAME_PAIR));
    addch('\n');
}

static void print_entry_table(const Database *db, const int *indexes, size_t index_count) {
    size_t w_desc = 11, w_user = 6, w_pw = 8, w_url = 6, w_tags = 6, w_cd = 6, w_ud = 6, w_status = 6;
    for (size_t i = 0; i < index_count; ++i) {
        const Entry *e = &db->items[indexes[i]];
        if (strlen(e->description) > w_desc) w_desc = strlen(e->description);
        if (strlen(e->user) > w_user) w_user = strlen(e->user);
        if (strlen(e->password) > w_pw) w_pw = strlen(e->password);
        if (strlen(e->url) > w_url) w_url = strlen(e->url);
        if (strlen(e->tags) > w_tags) w_tags = strlen(e->tags);
        if (strlen(e->createdate) > w_cd) w_cd = strlen(e->createdate);
        if (strlen(e->updatedate) > w_ud) w_ud = strlen(e->updatedate);
        if (strlen(e->status) > w_status) w_status = strlen(e->status);
    }
    if (w_desc > 40) w_desc = 40;
    if (w_user > 20) w_user = 20;
    if (w_pw > 24) w_pw = 24;
    if (w_url > 32) w_url = 32;
    if (w_tags > 24) w_tags = 24;

    print_separator();
    attron(COLOR_PAIR(BODY_PAIR));
    printw("%-4s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s\n", "ID",
           (int)w_desc, "Description",
           (int)w_user, "User",
           (int)w_pw, "Password",
           (int)w_url, "URL",
           (int)w_tags, "Tags",
           (int)w_cd, "Created",
           (int)w_ud, "Updated",
           (int)w_status, "Status");
    attroff(COLOR_PAIR(BODY_PAIR));
    print_separator();

    for (size_t i = 0; i < index_count; ++i) {
        const Entry *e = &db->items[indexes[i]];
        attron(COLOR_PAIR(BODY_PAIR));
        printw("%-4d %-*.*s %-*.*s %-*.*s %-*.*s %-*.*s %-*.*s %-*.*s %-*.*s\n",
               e->id,
               (int)w_desc, (int)w_desc, e->description,
               (int)w_user, (int)w_user, e->user,
               (int)w_pw, (int)w_pw, e->password,
               (int)w_url, (int)w_url, e->url,
               (int)w_tags, (int)w_tags, e->tags,
               (int)w_cd, (int)w_cd, e->createdate,
               (int)w_ud, (int)w_ud, e->updatedate,
               (int)w_status, (int)w_status, e->status);
        attroff(COLOR_PAIR(BODY_PAIR));
    }
    print_separator();
}

static void print_entry_detail(const Entry *e) {
    print_separator();
    attron(COLOR_PAIR(BODY_PAIR));
    printw("ID: %d\n", e->id);
    printw("Description: %s\n", e->description);
    printw("User: %s\n", e->user);
    printw("Password: %s\n", e->password);
    printw("URL: %s\n", e->url);
    printw("Tags: %s\n", e->tags);
    printw("Created: %s\n", e->createdate);
    printw("Last Update: %s\n", e->updatedate);
    printw("Status: %s\n", e->status);
    printw("Comment:\n%s\n", e->comment);
    attroff(COLOR_PAIR(BODY_PAIR));
    print_separator();
}

/* Wizards */
static void wizard_fill_entry(Entry *e, const char *user_default) {
    char input[MAX_LINE];

    printw("Description (%s): ", e->description);
    read_line(input, sizeof(input));
    if (strlen(input) > 0) strncpy(e->description, input, sizeof(e->description) - 1);

    printw("User (%s): ", strlen(user_default) > 0 ? user_default : e->user);
    read_line(input, sizeof(input));
    if (strlen(input) > 0) {
        strncpy(e->user, input, sizeof(e->user) - 1);
    } else if (strlen(user_default) > 0) {
        strncpy(e->user, user_default, sizeof(e->user) - 1);
    }

    printw("Generate password? (y/n): ");
    read_line(input, sizeof(input));
    if (tolower((unsigned char)input[0]) == 'y') {
        printw("Length: ");
        read_line(input, sizeof(input));
        int len = atoi(input);
        if (len <= 0 || len > MAX_PASSWORD) len = 16;
        printw("Mode (1=numbers, 2=alnum, 3=alnum+special): ");
        read_line(input, sizeof(input));
        int mode = atoi(input);
        if (mode < 1 || mode > 3) mode = 2;
        generate_password(e->password, sizeof(e->password), len, mode);
        printw("Generated password: %s\n", e->password);
    } else {
        printw("Password (%s): ", e->password);
        read_line(input, sizeof(input));
        if (strlen(input) > 0) strncpy(e->password, input, sizeof(e->password) - 1);
    }

    printw("URL (%s): ", e->url);
    read_line(input, sizeof(input));
    if (strlen(input) > 0) strncpy(e->url, input, sizeof(e->url) - 1);

    printw("Tags comma separated (%s): ", e->tags);
    read_line(input, sizeof(input));
    if (strlen(input) > 0) strncpy(e->tags, input, sizeof(e->tags) - 1);

    printw("Comment (%s): ", e->comment);
    read_line(input, sizeof(input));
    if (strlen(input) > 0) strncpy(e->comment, input, sizeof(e->comment) - 1);

    printw("Status (%s): ", e->status);
    read_line(input, sizeof(input));
    if (strlen(input) > 0) strncpy(e->status, input, sizeof(e->status) - 1);
}

/* Generators */
static void generate_password(char *out, size_t max_len, int length, int mode) {
    const char *digits = "0123456789";
    const char *letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char *special = ";.,#-_%&$+'";

    char charset[256] = {0};
    charset[0] = '\0';
    strncat(charset, digits, sizeof(charset) - strlen(charset) - 1);
    if (mode >= 2) {
        strncat(charset, letters, sizeof(charset) - strlen(charset) - 1);
    }
    if (mode >= 3) {
        strncat(charset, special, sizeof(charset) - strlen(charset) - 1);
    }

    size_t charset_len = strlen(charset);
    if (charset_len == 0) charset_len = 1;

    srand((unsigned int)time(NULL));
    for (int i = 0; i < length && (size_t)i + 1 < max_len; ++i) {
        out[i] = charset[rand() % charset_len];
    }
    out[length < (int)max_len ? length : (int)max_len - 1] = '\0';
}

/* CRUD helpers */
static void add_entry(Database *db) {
    if (db->count >= MAX_ENTRIES) {
    ui_clear_body();
    move(BODY_START_ROW, 0);
        print_error_line("Database full.");
        return;
    }
    ui_clear_body();
    move(3, 0);
    Entry e = {0};
    e.id = db->next_id++;
    strncpy(e.description, "New entry", sizeof(e.description) - 1);
    strncpy(e.user, "", sizeof(e.user) - 1);
    strncpy(e.password, "", sizeof(e.password) - 1);
    strncpy(e.url, "", sizeof(e.url) - 1);
    strncpy(e.comment, "", sizeof(e.comment) - 1);
    strncpy(e.tags, "", sizeof(e.tags) - 1);
    strncpy(e.status, "active", sizeof(e.status) - 1);
    now_string(e.createdate, sizeof(e.createdate));
    strncpy(e.updatedate, e.createdate, sizeof(e.updatedate) - 1);

    wizard_fill_entry(&e, "");
    now_string(e.updatedate, sizeof(e.updatedate));
    db->items[db->count++] = e;
    printw("Added entry with id %d\n", e.id);
    refresh();
}

static Entry *find_entry_by_id(Database *db, int id) {
    for (size_t i = 0; i < db->count; ++i) {
        if (db->items[i].id == id) return &db->items[i];
    }
    return NULL;
}

static void change_entry(Database *db, int id) {
    Entry *e = find_entry_by_id(db, id);
    if (!e) {
    ui_clear_body();
    move(BODY_START_ROW, 0);
        print_error_line("Entry not found.");
        return;
    }
    ui_clear_body();
    move(BODY_START_ROW, 0);
    wizard_fill_entry(e, e->user);
    now_string(e->updatedate, sizeof(e->updatedate));
    printw("Updated entry %d\n", id);
    refresh();
}

static void change_passwords_for_user(Database *db, const char *user) {
    char input[MAX_LINE];
    ui_clear_body();
    move(BODY_START_ROW, 0);
    printw("Are you sure you want to change all passwords for user '%s'? (y/n): ", user);
    read_line(input, sizeof(input));
    if (tolower((unsigned char)input[0]) != 'y') {
        printw("Cancelled.\n");
        refresh();
        return;
    }
    printw("Generate new password for all? (y/n): ");
    read_line(input, sizeof(input));
    bool generate = tolower((unsigned char)input[0]) == 'y';
    int len = 16;
    int mode = 2;
    char new_pw[MAX_PASSWORD + 1] = {0};
    if (generate) {
        printw("Length: ");
        read_line(input, sizeof(input));
        len = atoi(input);
        if (len <= 0 || len > MAX_PASSWORD) len = 16;
        printw("Mode (1=numbers, 2=alnum, 3=alnum+special): ");
        read_line(input, sizeof(input));
        mode = atoi(input);
        if (mode < 1 || mode > 3) mode = 2;
        generate_password(new_pw, sizeof(new_pw), len, mode);
    } else {
        printw("Enter new password: ");
        read_line(new_pw, sizeof(new_pw));
    }

    for (size_t i = 0; i < db->count; ++i) {
        if (strcasecmp_portable(db->items[i].user, user) == 0) {
            strncpy(db->items[i].password, new_pw, sizeof(db->items[i].password) - 1);
            now_string(db->items[i].updatedate, sizeof(db->items[i].updatedate));
        }
    }
    if (generate) {
        printw("New password for user '%s': %s\n", user, new_pw);
    }
    printw("Passwords updated.\n");
    refresh();
}

static void remove_entries(Database *db, int *ids, size_t id_count) {
    char input[MAX_LINE];
    ui_clear_body();
    move(BODY_START_ROW, 0);
    printw("Are you sure you want to delete ");
    for (size_t i = 0; i < id_count; ++i) {
        printw("%d%s", ids[i], (i + 1 < id_count) ? " " : "");
    }
    printw("? (y/n): ");
    read_line(input, sizeof(input));
    if (tolower((unsigned char)input[0]) != 'y') {
        printw("Cancelled.\n");
        refresh();
        return;
    }
    size_t write_idx = 0;
    for (size_t i = 0; i < db->count; ++i) {
        bool delete_me = false;
        for (size_t j = 0; j < id_count; ++j) {
            if (db->items[i].id == ids[j]) {
                delete_me = true;
                break;
            }
        }
        if (!delete_me) {
            db->items[write_idx++] = db->items[i];
        }
    }
    db->count = write_idx;
    printw("Deletion complete.\n");
    refresh();
}

/* Commands */
static void print_help(void) {
    ui_clear_body();
    move(BODY_START_ROW, 0);
    print_separator();
    attron(COLOR_PAIR(BODY_PAIR));
    printw("Commands:\n");
    printw("  help                          Show this help\n");
    printw("  show all                      List all passwords in table view\n");
    printw("  show tag <t1> [t2 ...]        List entries matching any tag\n");
    printw("  show <id>                     Show entry detail by id\n");
    printw("  show user <name>              List entries for user\n");
    printw("  show url <url>                List entries matching url\n");
    printw("  show date <dd.mm.yyyy>        List entries created/updated on date\n");
    printw("  show status <value>           List entries by status\n");
    printw("  add pw                        Add new password (wizard)\n");
    printw("  change <id>                   Edit entry fields (wizard)\n");
    printw("  change pw <user>              Change all passwords for user\n");
    printw("  rm pw <id1> [id2 ...]         Remove entries by id (confirm)\n");
    printw("  version                       Show version and author info\n");
    printw("  lock                          Lock vault and require master password\n");
    printw("  clear                         Clear screen\n");
    printw("  quit/exit/q                   Exit\n");
    attroff(COLOR_PAIR(BODY_PAIR));
    print_separator();
    refresh();
}

static void show_filtered(const Database *db, const int *indexes, size_t count) {
    ui_clear_body();
    move(BODY_START_ROW, 0);
    if (count == 0) {
        print_error_line("No entries found.");
        return;
    }
    print_entry_table(db, indexes, count);
    refresh();
}

static void handle_show(Database *db, char **tokens, int token_count) {
    int indexes[MAX_ENTRIES];
    size_t idx_count = 0;

    if (token_count == 1 || (token_count == 2 && strcmp(tokens[1], "all") == 0)) {
        for (size_t i = 0; i < db->count; ++i) indexes[idx_count++] = (int)i;
        show_filtered(db, indexes, idx_count);
        return;
    }
    if (token_count >= 3 && strcmp(tokens[1], "tag") == 0) {
        for (size_t i = 0; i < db->count; ++i) {
            for (int t = 2; t < token_count; ++t) {
                if (matches_tag(db->items[i].tags, tokens[t])) {
                    indexes[idx_count++] = (int)i;
                    break;
                }
            }
        }
        show_filtered(db, indexes, idx_count);
        return;
    }
    if (token_count == 3 && strcmp(tokens[1], "user") == 0) {
        for (size_t i = 0; i < db->count; ++i) {
            if (strcasecmp_portable(db->items[i].user, tokens[2]) == 0) {
                indexes[idx_count++] = (int)i;
            }
        }
        show_filtered(db, indexes, idx_count);
        return;
    }
    if (token_count == 3 && strcmp(tokens[1], "url") == 0) {
        for (size_t i = 0; i < db->count; ++i) {
            if (contains_case_insensitive(db->items[i].url, tokens[2])) {
                indexes[idx_count++] = (int)i;
            }
        }
        show_filtered(db, indexes, idx_count);
        return;
    }
    if (token_count == 3 && strcmp(tokens[1], "date") == 0) {
        const char *date = tokens[2];
        for (size_t i = 0; i < db->count; ++i) {
            if (strncmp(db->items[i].createdate, date, strlen(date)) == 0 ||
                strncmp(db->items[i].updatedate, date, strlen(date)) == 0) {
                indexes[idx_count++] = (int)i;
            }
        }
        show_filtered(db, indexes, idx_count);
        return;
    }
    if (token_count == 3 && strcmp(tokens[1], "status") == 0) {
        for (size_t i = 0; i < db->count; ++i) {
            if (strcasecmp_portable(db->items[i].status, tokens[2]) == 0) {
                indexes[idx_count++] = (int)i;
            }
        }
        show_filtered(db, indexes, idx_count);
        return;
    }
    if (token_count == 2) {
        int id = atoi(tokens[1]);
        Entry *e = find_entry_by_id(db, id);
        if (!e) {
            ui_clear_body();
            move(BODY_START_ROW, 0);
            print_error_line("Not found.");
        } else {
            ui_clear_body();
            move(BODY_START_ROW, 0);
            print_entry_detail(e);
            refresh();
        }
        return;
    }
    ui_clear_body();
    move(BODY_START_ROW, 0);
    print_error_line("Invalid show command.");
}

/* Authentication */
static bool prompt_master_password(char *out, size_t size, bool first_time) {
    char input[MAX_PASSWORD + 4];
    char confirm[MAX_PASSWORD + 4];
    if (first_time) {
        ui_center_box("Welcome",
                      "No database found.\n"
                      "A new encrypted vault will be created.\n"
                      "Choose a master password (min 8 chars).");
        while (true) {
            if (!prompt_password("Type new master password: ", input, sizeof(input))) return false;
            if (strlen(input) < 8) {
                ui_draw_divider();
                move(LINES - 1, 0);
                clrtoeol();
                printw("Password too short (min 8).");
                refresh();
                napms(1500);
                continue;
            }
            if (!prompt_password("Type again: ", confirm, sizeof(confirm))) return false;
            if (strcmp(input, confirm) != 0) {
                ui_draw_divider();
                move(LINES - 1, 0);
                clrtoeol();
                printw("Password mismatch. Try again.");
                refresh();
                napms(1500);
                continue;
            }
            strncpy(out, input, size - 1);
            out[size - 1] = '\0';
            return true;
        }
    }
    for (int attempt = 0; attempt < 3; ++attempt) {
        ui_center_box("Unlock Vault", "Enter your master password.");
        if (!prompt_password("Master password: ", input, sizeof(input))) return false;
        strncpy(out, input, size - 1);
        out[size - 1] = '\0';
        return true;
    }
    return false;
}

static bool unlock_vault(Database *db, char *master) {
    int attempts = 0;
    while (attempts < 3) {
        if (!prompt_master_password(master, MAX_PASSWORD, false)) {
            attempts++;
            continue;
        }
        if (strlen(master) == 0) {
            attempts++;
            continue;
        }
        if (load_database(db, db_path, master)) {
            db_status = DB_STATUS_ONLINE;
            ui_draw_header(db_status);
            return true;
        }
        ui_show_message("Unlock failed", "Invalid password or corrupted DB.", 1500, true);
        attempts++;
    }
    return false;
}

/* Main loop */
int main(int argc, char **argv) {
    /* Resolve DB path */
    if (getuid() == 0) {
        snprintf(db_path, sizeof(db_path), "/var/lib/%s/%s", PROGRAM_NAME, "vault.db");
    } else {
        const char *home = getenv("HOME");
        if (!home) home = ".";
        snprintf(db_path, sizeof(db_path), "%s/.vault.db", home);
    }
    ensure_dir_for_path(db_path);

    /* CLI flags */
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("%s v%s\nUsage: %s [options]\n  -h, --help     Show this help\n  -V, --version  Show version and author info\n", PROGRAM_NAME, PROGRAM_VERSION, PROGRAM_NAME);
            return 0;
        }
        if (strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("%s v%s\nAuthor: %s\n", PROGRAM_NAME, PROGRAM_VERSION, PROGRAM_AUTHOR);
            return 0;
        }
    }

    Database db = {.count = 0, .next_id = 1};
    char master[MAX_PASSWORD + 1] = {0};

    ui_init();
    ui_clear_body();
    ui_draw_header(db_status);
    move(BODY_START_ROW, 0);
    attron(COLOR_PAIR(BODY_PAIR));
    printw("Simple Vault\n");
    printw("Database file: %s\n\n", db_path);
    attroff(COLOR_PAIR(BODY_PAIR));
    refresh();

    bool db_exists = file_exists(db_path);
    bool new_db_created = false;
    if (!db_exists) {
        if (!prompt_master_password(master, sizeof(master), true)) {
            ui_shutdown();
            fprintf(stderr, "Could not set master password.\n");
            return 1;
        }
        if (!save_database(&db, db_path, master)) {
            ui_shutdown();
            fprintf(stderr, "Failed to initialize database.\n");
            return 1;
        }
        ui_show_message("Vault created", "New database has been initialized.\n\nType \"help\" to see available commands.", 3000, false);
        db_status = DB_STATUS_ONLINE;
        ui_draw_header(db_status);
        new_db_created = true;
    }

    int attempts = 0;
    bool loaded = new_db_created;
    while (attempts < 3 && !loaded) {
        if (!prompt_master_password(master, sizeof(master), false)) {
            attempts++;
            continue;
        }
        if (strlen(master) == 0) {
            attempts++;
            continue;
        }
        if (load_database(&db, db_path, master)) {
            loaded = true;
            db_status = DB_STATUS_ONLINE;
            ui_draw_header(db_status);
        } else {
            ui_show_message("Unlock failed", "Invalid password or corrupted DB.", 1500, true);
            attempts++;
        }
    }
    if (!loaded) {
        ui_show_message("Unlock failed", "Master password incorrect or database corrupted.\nExiting...", 2000, true);
        ui_shutdown();
        fprintf(stderr, "Failed to open database: master password incorrect or database corrupted.\n");
        return 1;
    }
    if (!new_db_created) {
        ui_show_message("Unlocked", "Vault decrypted.\nType \"help\" to see available commands.", 4000, true);
    }

    char input_line[MAX_LINE];
    char *tokens[16];
    while (true) {
        if (!prompt_command("> ", input_line, sizeof(input_line))) break;
        if (strlen(input_line) == 0) continue;

        int token_count = 0;
        char *tok = strtok(input_line, " ");
        while (tok && token_count < 16) {
            tokens[token_count++] = tok;
            tok = strtok(NULL, " ");
        }
        if (token_count == 0) continue;

        if (strcmp(tokens[0], "help") == 0) {
            print_help();
        } else if (strcmp(tokens[0], "show") == 0) {
            handle_show(&db, tokens, token_count);
        } else if (strcmp(tokens[0], "add") == 0 && token_count >= 2 && strcmp(tokens[1], "pw") == 0) {
            add_entry(&db);
            save_database(&db, db_path, master);
        } else if (strcmp(tokens[0], "change") == 0 && token_count == 2) {
            int id = atoi(tokens[1]);
            change_entry(&db, id);
            save_database(&db, db_path, master);
        } else if (strcmp(tokens[0], "change") == 0 && token_count == 3 && strcmp(tokens[1], "pw") == 0) {
            change_passwords_for_user(&db, tokens[2]);
            save_database(&db, db_path, master);
        } else if (strcmp(tokens[0], "rm") == 0 && token_count >= 3 && strcmp(tokens[1], "pw") == 0) {
            int ids[14];
            size_t id_count = 0;
            for (int i = 2; i < token_count && id_count < 14; ++i) {
                ids[id_count++] = atoi(tokens[i]);
            }
            remove_entries(&db, ids, id_count);
            save_database(&db, db_path, master);
        } else if (strcmp(tokens[0], "version") == 0) {
            ui_clear_body();
            move(BODY_START_ROW, 0);
            attron(COLOR_PAIR(FRAME_PAIR));
            printw("%s", PROGRAM_NAME);
            attroff(COLOR_PAIR(FRAME_PAIR));
            printw(" v%s\n", PROGRAM_VERSION);
            attron(COLOR_PAIR(BODY_PAIR));
            printw("Author: %s\n", PROGRAM_AUTHOR);
            printw("License: %s\n", PROGRAM_LICENSE);
            attroff(COLOR_PAIR(BODY_PAIR));
            refresh();
        } else if (strcmp(tokens[0], "clear") == 0) {
            ui_clear_body();
            refresh();
        } else if (strcmp(tokens[0], "lock") == 0) {
            save_database(&db, db_path, master);
            db_status = DB_STATUS_OFFLINE;
            ui_draw_header(db_status);
            ui_clear_body();
            move(BODY_START_ROW, 0);
            printw("Vault locked. Enter master password to continue.\n");
            refresh();
            if (!unlock_vault(&db, master)) {
                ui_show_message("Unlock failed", "Exiting...", 1500, true);
                break;
            }
        } else if (strcmp(tokens[0], "quit") == 0 || strcmp(tokens[0], "exit") == 0 || strcmp(tokens[0], "q") == 0) {
            save_database(&db, db_path, master);
            break;
        } else {
            ui_clear_body();
            move(BODY_START_ROW, 0);
            print_error_line("Unknown command. Type 'help'.");
        }
    }
    ui_shutdown();
    return 0;
}
