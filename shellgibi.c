#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>            //termios, TCSANOW, ECHO, ICANON
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>

#define HISTORY_SIZE 10
const char * sysname = "shellgibi";

char* history[HISTORY_SIZE];    // custom command: an array to keep the history of commands
int curind=0;
int histflag=0;

enum return_codes {
    SUCCESS = 0,
    EXIT = 1,
    UNKNOWN = 2,
};
struct command_t {
    char *name;
    bool background;
    bool auto_complete;
    int arg_count;
    char **args;
    char *redirects[3]; // in/out redirection
    struct command_t *next; // for piping
};
const char* findPath(char *cmd);
void runPipe (struct command_t *command, int fdtmp);
/**
 * Prints a command struct
 * @param struct command_t *
 */
void print_command(struct command_t * command)
{
    int i=0;
    printf("Command: <%s>\n", command->name);
    printf("\tIs Background: %s\n", command->background?"yes":"no");
    printf("\tNeeds Auto-complete: %s\n", command->auto_complete?"yes":"no");
    printf("\tRedirects:\n");
    for (i=0;i<3;i++)
        printf("\t\t%d: %s\n", i, command->redirects[i]?command->redirects[i]:"N/A");
    printf("\tArguments (%d):\n", command->arg_count);
    for (i=0;i<command->arg_count;++i)
        printf("\t\tArg %d: %s\n", i, command->args[i]);
    if (command->next)
    {
        printf("\tPiped to:\n");
        print_command(command->next);
    }


}
/**
 * Release allocated memory of a command
 * @param  command [description]
 * @return         [description]
 */
int free_command(struct command_t *command)
{
    if (command->arg_count)
    {
        for (int i=0; i<command->arg_count; ++i)
            free(command->args[i]);
        free(command->args);
    }
    for (int i=0;i<3;++i)
        if (command->redirects[i])
            free(command->redirects[i]);
    if (command->next)
    {
        free_command(command->next);
        command->next=NULL;
    }
    free(command->name);
    free(command);
    return 0;
}
/**
 * Show the command prompt
 * @return [description]
 */
int show_prompt()
{
    char cwd[1024], hostname[1024];
    gethostname(hostname, sizeof(hostname));
    getcwd(cwd, sizeof(cwd));
    printf("%s@%s:%s %s$ ", getenv("USER"), hostname, cwd, sysname);
    return 0;
}
/**
 * Parse a command string into a command struct
 * @param  buf     [description]
 * @param  command [description]
 * @return         0
 */
int parse_command(char *buf, struct command_t *command)
{
    const char *splitters=" \t"; // split at whitespace
    int index, len;
    len=strlen(buf);
    while (len>0 && strchr(splitters, buf[0])!=NULL) // trim left whitespace
    {
        buf++;
        len--;
    }
    while (len>0 && strchr(splitters, buf[len-1])!=NULL)
        buf[--len]=0; // trim right whitespace

    if (len>0 && buf[len-1]=='?') // auto-complete
        command->auto_complete=true;
    if (len>0 && buf[len-1]=='&') // background
        command->background=true;

    char *pch = strtok(buf, splitters);
    command->name=(char *)malloc(strlen(pch)+1);
    if (pch==NULL)
        command->name[0]=0;
    else
        strcpy(command->name, pch);

    command->args=(char **)malloc(sizeof(char *));

    int redirect_index;
    int arg_index=0;
    char temp_buf[1024], *arg;
    while (1)
    {
        // tokenize input on splitters
        pch = strtok(NULL, splitters);
        if (!pch) break;
        arg=temp_buf;
        strcpy(arg, pch);
        len=strlen(arg);

        if (len==0) continue; // empty arg, go for next
        while (len>0 && strchr(splitters, arg[0])!=NULL) // trim left whitespace
        {
            arg++;
            len--;
        }
        while (len>0 && strchr(splitters, arg[len-1])!=NULL) arg[--len]=0; // trim right whitespace
        if (len==0) continue; // empty arg, go for next

        // piping to another command
        if (strcmp(arg, "|")==0)
        {
            struct command_t *c=malloc(sizeof(struct command_t));
            int l=strlen(pch);
            pch[l]=splitters[0]; // restore strtok termination
            index=1;
            while (pch[index]==' ' || pch[index]=='\t') index++; // skip whitespaces

            parse_command(pch+index, c);
            pch[l]=0; // put back strtok termination
            command->next=c;
            continue;
        }

        // background process
        if (strcmp(arg, "&")==0)
            continue; // handled before

        // handle input redirection
        redirect_index=-1;
        if (arg[0]=='<')
            redirect_index=0;
        if (arg[0]=='>')
        {
            if (len>1 && arg[1]=='>')
            {
                redirect_index=2;
                arg++;
                len--;
            }
            else redirect_index=1;
        }
        if (redirect_index != -1)
        {
            command->redirects[redirect_index]=malloc(len);
            strcpy(command->redirects[redirect_index], arg);
            continue;
        }

        // normal arguments
        if (len>2 && ((arg[0]=='"' && arg[len-1]=='"')
                      || (arg[0]=='\'' && arg[len-1]=='\''))) // quote wrapped arg
        {
            arg[--len]=0;
            arg++;
        }
        command->args=(char **)realloc(command->args, sizeof(char *)*(arg_index+1));
        command->args[arg_index]=(char *)malloc(len+1);
        strcpy(command->args[arg_index++], arg);
    }
    command->arg_count=arg_index;
    return 0;
}
void prompt_backspace()
{
    putchar(8); // go back 1
    putchar(' '); // write empty over
    putchar(8); // go back 1 again
}
/**
 * Prompt a command from the user
 * @param  buf      [description]
 * @param  buf_size [description]
 * @return          [description]
 */
int prompt(struct command_t *command)
{
    int index=0;
    char c;
    char buf[4096];
    static char oldbuf[4096];

    // tcgetattr gets the parameters of the current terminal
    // STDIN_FILENO will tell tcgetattr that it should write the settings
    // of stdin to oldt
    static struct termios backup_termios, new_termios;
    tcgetattr(STDIN_FILENO, &backup_termios);
    new_termios = backup_termios;
    // ICANON normally takes care that one line at a time will be processed
    // that means it will return if it sees a "\n" or an EOF or an EOL
    new_termios.c_lflag &= ~(ICANON | ECHO); // Also disable automatic echo. We manually echo each char.
    // Those new settings will be set to STDIN
    // TCSANOW tells tcsetattr to change attributes immediately.
    tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);


    //FIXME: backspace is applied before printing chars
    show_prompt();
    int multicode_state=0;
    buf[0]=0;
    while (1)
    {
        c=getchar();
        // printf("Keycode: %u\n", c); // DEBUG: uncomment for debugging
        if (c==32 && index==0)
            continue;
        
        if (c==9) // handle tab
        {
            buf[index++]='?'; // autocomplete
            break;
        }

        if (c==127) // handle backspace
        {
            if (index>0)
            {
                prompt_backspace();
                index--;
            }
            continue;
        }
        if (c==27 && multicode_state==0) // handle multi-code keys
        {
            multicode_state=1;
            continue;
        }
        if (c==91 && multicode_state==1)
        {
            multicode_state=2;
            continue;
        }
        if (c==65 && multicode_state==2) // up arrow
        {
            int i;
            while (index>0)
            {
                prompt_backspace();
                index--;
            }
            for (i=0;oldbuf[i];++i)
            {
                putchar(oldbuf[i]);
                buf[i]=oldbuf[i];
            }
            index=i;
            continue;
        }
        else
            multicode_state=0;

        putchar(c); // echo the character
        buf[index++]=c;
        if (index>=sizeof(buf)-1) break;
        if (c=='\n') // enter key
            break;
        if (c==4) // Ctrl+D
            return EXIT;
    }
    if (index>0 && buf[index-1]=='\n') // trim newline from the end
        index--;
    buf[index++]=0; // null terminate string

    strcpy(oldbuf, buf);

    if(strlen(buf)>0)    // to handle enter dump error
        parse_command(buf, command);

     //print_command(command); // DEBUG: uncomment for debugging

    // restore the old settings
    tcsetattr(STDIN_FILENO, TCSANOW, &backup_termios);
    return SUCCESS;
}
int process_command(struct command_t *command);
int main()
{

    // for custom command history initialization performed below
    for(int i=0;i<HISTORY_SIZE;i++) {
        history[i]=malloc(100 * sizeof(char));
    }

    while (1)
    {
        struct command_t *command=malloc(sizeof(struct command_t));
        memset(command, 0, sizeof(struct command_t)); // set all bytes to 0

        int code;
        code = prompt(command);
        if (code==EXIT) break;

        if(command->name!=NULL)
            code = process_command(command);
        if (code==EXIT) break;

        free_command(command);
    }

    printf("\n");
    return 0;
}

int process_command(struct command_t *command)
{
    int r;
    if (strcmp(command->name, "")==0) return SUCCESS;

    if (strcmp(command->name, "exit")==0)
        return EXIT;


    if (command->args[0]!=NULL) {
        if (command->args[1]!=NULL) {   // store the command with two parameters
            strcpy(history[curind], command->name);
            strcat(history[curind]," ");
            strcat(history[curind],command->args[0]);
            strcat(history[curind]," ");
            strcat(history[curind],command->args[1]);
        }
        else {  // store the command with one parameter
            strcpy(history[curind], command->name);
            strcat(history[curind]," ");
            strcat(history[curind],command->args[0]);
        }
    }
    else // store the command without parameter
        strcpy(history[curind],command->name);

    if (histflag == 0 && curind==HISTORY_SIZE-1)  // history is kept in the same array with cyclic array
        histflag=1;
    curind=(curind+1)%HISTORY_SIZE;


    if (strcmp(command->name, "cd")==0)
    {
        if (command->arg_count > 0)
        {
            r=chdir(command->args[0]);
            if (r==-1)
                printf("-%s: %s: %s\n", sysname, command->name, strerror(errno));
            return SUCCESS;
        }
    }
    if (strcmp(command->name, "myjobs")==0) {  // lists the user's processes

        char cmd[100];
        strcpy(cmd,"ps -fU ");
        strcat(cmd,getenv("USER"));
        strcat(cmd," -eo pid,cmd,stat");
        system(cmd);
        return SUCCESS;
    }
    if (strcmp(command->name, "pause")==0) {   // suspends the given process

        char cmd[100];
        strcpy(cmd, "kill -TSTP ");
        strcat(cmd, command->args[0]);
        system(cmd);
        return SUCCESS;
    }
    if (strcmp(command->name, "mybg")==0) { // puts a paused process at the background in running state

        char cmd[100];
        strcpy(cmd, "kill -CONT ");
        strcat(cmd, command->args[0]);
        system(cmd);
        return SUCCESS;
    }
    if (strcmp(command->name, "myfg")==0) {  // puts a paused process at the foreground in running state

        char cmd[100];

        strcpy(cmd, "kill -CONT ");
        strcat(cmd, command->args[0]);
        system(cmd);

        return SUCCESS;
    }

    if (strcmp(command->name, "alarm")==0) {  // sets an alarm at the specified time playing the specified .wav file
        char cmd[100];
        char min[2],hr[2];
        if (command->args[0][1]=='.') {
            hr[0]=command->args[0][0];
            min[0]=command->args[0][2];
            min[1]=command->args[0][3];
        }
        else {
            hr[0]=command->args[0][0];
            hr[1]=command->args[0][1];
            min[0]=command->args[0][3];
            min[1]=command->args[0][4];
        }

        char curdir[FILENAME_MAX];
        getcwd( curdir, FILENAME_MAX );

        strcpy(cmd,"echo \"");
        strcat(cmd,min);
        strcat(cmd," ");
        strcat(cmd,hr);
        strcat(cmd," * * * aplay ");
        strcat(cmd,curdir);
        strcat(cmd,"/");
        strcat(cmd,command->args[1]);
        strcat(cmd,"\" > crontemp.txt");

        system(cmd);
        system("crontab -r");
        system("crontab crontemp.txt");
        system("rm crontemp.txt");

        return SUCCESS;
    }

    if (strcmp(command->name, "history")==0) {   // custom command 1: shows commands in the history
        int histsize;
        if (histflag)
            histsize = HISTORY_SIZE;
        else histsize = curind;

        for (int i = histsize - 1; i >= 0; i--) {
            printf("%s\n", history[i]);
        }
        return SUCCESS;
    }
    if (strcmp(command->name, "wait")==0) {    // custom command 2: waits for the specified time in seconds
        if (command->args[0]==NULL) {
            fprintf(stderr, "No parameters in wait \n");
            exit(0);
        }
        int sec=atoi(command->args[0]);
        sleep(sec);
        printf("Waited for %d secs\n", sec);
        return SUCCESS;
    }

    if (strcmp(command->name, "lshome")==0) {  // custom command 3: lists the home folder content
        char cmd[100];
        strcpy(cmd,"ls ");
        strcat(cmd,getenv("HOME"));
        system(cmd);
        return SUCCESS;
    }

    int outputfile;
    pid_t pid=fork();


    if (pid==0) // child
    {

        command->args = (char **) realloc(
                command->args, sizeof(char *) * (command->arg_count += 2));

        // shift everything forward by 1
        for (int i = command->arg_count - 2; i > 0; --i)
            command->args[i] = command->args[i - 1];

        // set args[0] as a copy of name
        command->args[0] = strdup(command->name);
        // set args[arg_count-1] (last) to NULL
        command->args[command->arg_count - 1] = NULL;

        command->arg_count--;

        if (command->auto_complete) {   // when Tab key pressed  autocomplete part is executed

            char environment[1000];

            int currentdir=0;
            if (command->name[1] == '/' && command->name[0] == '.') {  // if current folder is specified it doesnt look at other paths

                strcat(environment, "./");
                currentdir=1;
            }
            else {
                strcpy(environment, getenv("PATH"));  // gets all path definitions from the environment.

            }
                char name[100];
                strcat(environment, ":");
                strcpy(name,command->name);
                name[strlen(name)-1]='*';
                char *path;
                path=strtok(environment, ":");

                while (path != NULL) {   // for each folder in the path, it is searched
                    size_t size = snprintf(NULL, 0, "%s/%s*", path, command->name);
                    char *tmp = (char *)malloc(size + 1);
                    if (tmp == NULL)
                        exit(EXIT_FAILURE);

                    strcpy(tmp, path);
                    strcat(tmp, "/");
                    strcat(tmp, name);

                    if (currentdir==1)
                        strcpy(tmp,name);
                    char arg[100]="ls -1 ";
                    strcat(arg,tmp);
                    strcat(arg," >> y.txt 2> /dev/null");  // creates a folder named y.txt and y.txt contains all the appropriate commands
                    system(arg);
                    path = strtok(NULL, ":");

                    free(tmp);
                }
                FILE *fptr;
                char line[100000], tmpLine[100000];
                int counter=0;

                if ( (fptr = fopen ("y.txt", "r")) == NULL) {
                    printf("Error! opening file");
                    exit(1);
                }


            printf("\n");
                while(fscanf(fptr, "%s[^\n]", line) != EOF) {    // read each line of the temporary y.txt file
                    printf("%s\n", line);
                    counter++;
                }
                printf("\n");
                fclose(fptr);
                system("rm y.txt  2> /dev/null");    // remove y.txt

                if(counter==1){    // if there is only one item in the list it is being executed
                    strcpy(tmpLine,line);
                    size_t size = snprintf(NULL, 0, "%s*", line);
                    char *token=(char *)malloc(size + 1);
                    char *prvtoken=(char *)malloc(size + 1);;
                    token=strtok(tmpLine, "/");

                    while (token != NULL) {
                        prvtoken=token;
                        token = strtok(NULL, "/");
                    }

                    strcat(prvtoken,"?");
                    strcpy(command->args[0],line);

                    if (strcmp(prvtoken,command->name))
                        execv(line, command->args);
                    else {
                        system("ls");  // if the command is fully typed, current folder is listed
                    }
                }


        }

        // I/O Redirection
        if(command->redirects[1]!=NULL){  // output redirection with '>'
            outputfile = open(command->args[command->arg_count-1],  O_WRONLY | O_CREAT | O_TRUNC ,S_IRUSR | S_IWUSR | S_IRGRP);
            dup2(outputfile,1);
            close(outputfile);
            command->args[command->arg_count-1]=NULL;


        }else if(command->redirects[2]!=NULL){ // output redirection with '>>'
            outputfile = open(command->args[command->arg_count-1], O_WRONLY | O_CREAT | O_APPEND,S_IRUSR | S_IWUSR | S_IRGRP);
            dup2(outputfile,1);
            close(outputfile);
            command->args[command->arg_count-1]=NULL;
        }else if(command->redirects[0]!= NULL){ // input redirection with '<'
            FILE *fptr;

            char input[100]={"input"};

            fptr = fopen (command->args[1], "r");

            fgets(input,100,fptr);
            input[strlen(input)-1]='\0';

            char *const *inputfile= (char *const *) input;
            execv(command->name, inputfile);

        } else if(command->next != NULL) {  // pipe redirection
            runPipe(command,STDIN_FILENO);  // all pipe related actions
            return SUCCESS;
        }

        /// TODO: do your own exec with path resolving using execv()
        if (command->name[0] == '/' || command->name[0] == '.') {
            execv(command->name, command->args);
        }

        else {

            const char *path2;
            path2=findPath(command->name);  // find the path from the name of the command
            execv(path2, command->args);  // using the path of the command, execute the command
        }

        exit(0);


    }
    else
    {
        if (!command->background)
            wait(0); // wait for child process to finish
        return SUCCESS;
    }



}

const char* findPath(char *cmd) {    // this method finds the path of any command using its name

    FILE *fptr;
    char *path=malloc(100);
    char arg[100]="which ";
    strcat(arg,cmd);
    strcat(arg," > x.txt");  // the method creates a file called x.txt using output redirection.
                                // The file contains the path of the command
    system(arg);

    fptr = fopen ("x.txt", "r");   // read the path from x.txt
    fgets(path,100,fptr);
    path[strlen(path)-1]='\0';
    system("rm x.txt");  // remove x.txt
    return path;
}



void runPipe (struct command_t *command, int fdtmp) {   // this recursive method performs all required activities for pipe

    if (command->next==NULL) {  // if the last command is reached at command->next
        const char *path=findPath(command->name);
        dup2(fdtmp, 0);       // already opened file descriptor is being used as input.
        if (command->arg_count>0) {
            if (strcmp(command->name,command->args[0])!=0) {
                command->args = (char **) realloc(
                        command->args, sizeof(char *) * (command->arg_count += 1));

                for (int i = command->arg_count - 1; i > 0; --i)
                    command->args[i] = command->args[i - 1];

                command->args[0] = strdup(command->name);
            }
        }
        execv(path, command->args);
        return;
    }

    int fdpipe[2];

    if(pipe(fdpipe) == -1) {
        fprintf(stderr, "pipe error\n");
        exit(1);
    }

    struct command_t *cmdtmp;
    cmdtmp = command->next;

    const char *path1=findPath(command->name);
    const char *path2=findPath(cmdtmp->name);


    if(fork() == 0)    // the first command is executed
    {
        dup2(fdtmp,0);
        dup2(fdpipe[1], 1);
        close(fdpipe[0]);
        if (command->arg_count>0) {
            if (strcmp(command->name,command->args[0])!=0) {
                command->args = (char **) realloc(
                        command->args, sizeof(char *) * (command->arg_count += 1));

                for (int i = command->arg_count - 1; i > 0; --i)
                    command->args[i] = command->args[i - 1];

                command->args[0] = strdup(command->name);
            }
        }
        execv(path1, command->args);
    }
    else {  // when the child finishes execution runPipe() is recursively called again to execute the rest of the commands in the command->next
        wait(0);
        close(fdpipe[1]);
        if (cmdtmp->arg_count==0) {
            cmdtmp->args = (char **) realloc(
                    cmdtmp->args, sizeof(char *) * (cmdtmp->arg_count += 1));

            cmdtmp->args[0] = strdup(cmdtmp->name);
        }
        runPipe(cmdtmp,fdpipe[0]);
        return;
    }
}
