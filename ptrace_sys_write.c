#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#define ANSI_COLOR_ROJO    "\x1b[41m"
#define ANSI_COLOR_VERDE   "\x1b[42m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define TEXTO_A_REEMPLAZAR "prueba"
#define TEXTO_DE_REEMPLAZO "modificado"
#define TAMAÑO_CHUNK 4096

void hijo() {
    // configura el proceso hijo para que pueda ser rastreado por ptrace
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    int dev_nulo = open("/dev/null", O_WRONLY);
    dup2(dev_nulo, STDOUT_FILENO);
    close(dev_nulo);
    execl("/bin/echo", "/bin/echo", "Hola,", "mundo!,", "prueba", "quantum", "prueba", NULL);
    perror("execl");
}

void padre(pid_t pid) {
    int estado;
    size_t longitud_texto = 0;
    size_t longitud_maxima = 4096;

    waitpid(pid, &estado, 0);
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
    while (!WIFEXITED(estado)) {
        // continua la ejecución del proceso hijo y espera a que se pare en una syscall
        struct user_regs_struct estado_proceso;
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        waitpid(pid, &estado, 0);
        
        // verifica si el proceso hijo se paró en una syscall
        if (WIFSTOPPED(estado) && WSTOPSIG(estado) & 0x80) {
            // obtiene el estado de los registros del proceso hijo usando PTRACE_GETREGS
            ptrace(PTRACE_GETREGS, pid, 0, &estado_proceso);
            // imprime el número de la syscall y el retun address, es necesario usar state.orig_rax para guardarlo ya que cuando se detecta la syscall, rax se remplaza
            printf("SYSCALL %5lld en %#016llx\n", estado_proceso.orig_rax, estado_proceso.rip);

            // verifica si la lsyscall es sys_write 
            if (estado_proceso.orig_rax == 1) { // sys_write
                char *syscall_texto = malloc(TAMAÑO_CHUNK); // reserva un chunk para el texto de sys_write leído de la memoria del proceso hijo
                if (syscall_texto == NULL) {
                    exit(EXIT_FAILURE);
                }
                while (1) {
                    if (longitud_texto + sizeof(long) > longitud_maxima) {
                        longitud_maxima *= 2;
                        char *nuevo_texto = realloc(syscall_texto, longitud_maxima);
                        if (nuevo_texto == NULL) {
                            free(syscall_texto);
                            exit(EXIT_FAILURE);
                        }
                        syscall_texto = nuevo_texto;
                    }
                    long texto_hijo = ptrace(PTRACE_PEEKDATA, pid, estado_proceso.rsi + longitud_texto, 0);
                    memcpy(syscall_texto + longitud_texto, &texto_hijo, sizeof(texto_hijo));
                    longitud_texto += sizeof(texto_hijo);
                    if (memchr(&texto_hijo, '\0', sizeof(texto_hijo)) != NULL) {
                        break;
                    }
                }
                printf(ANSI_COLOR_ROJO "Texto antes de modificarse: %s" ANSI_COLOR_RESET, syscall_texto);
                
                // reemplaza todas las ocurrencias de "TEXTO_A_REEMPLAZAR" con "TEXTO_DE_REEMPLAZO"
                char *pos_reemplazo = syscall_texto;
                size_t longitud_remplazo = strlen(TEXTO_DE_REEMPLAZO);
                while ((pos_reemplazo = strstr(pos_reemplazo, TEXTO_A_REEMPLAZAR)) != NULL) {
                    memmove(pos_reemplazo + longitud_remplazo, pos_reemplazo + strlen(TEXTO_A_REEMPLAZAR), syscall_texto + longitud_texto - (pos_reemplazo + strlen(TEXTO_A_REEMPLAZAR)));
                    memcpy(pos_reemplazo, TEXTO_DE_REEMPLAZO, longitud_remplazo);
                    longitud_texto += longitud_remplazo - strlen(TEXTO_A_REEMPLAZAR);
                    /*
                    pos_reemplazo + longitud_remplazo: se refiere a la posición en la que se moverán los caracteres después de la cadena original.
                    pos_reemplazo + strlen(TEXTO_A_REEMPLAZAR): esta es la posición en la que termina la cadena original, se desplaza desde la posicion actual de pos_reemplazo
                    syscall_texto + longitud_texto - (pos_reemplazo + strlen(TEXTO_A_REEMPLAZAR)): para saber cuantos caracteres deben moverse después de la cadena original
                    */
                }
                
                printf(ANSI_COLOR_VERDE "Texto después de modificarse: %s" ANSI_COLOR_RESET, syscall_texto);
                
                // escribe el texto modificado en la memoria del proceso hijo
                for (size_t i = 0; i < longitud_texto; i += sizeof(long)) {
                    long datos;
                    memcpy(&datos, syscall_texto + i, sizeof(long));
                    ptrace(PTRACE_POKEDATA, pid, estado_proceso.rsi + i, datos);
                }
                free(syscall_texto);
            }
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
            waitpid(pid, &estado, 0);
        }
    }
}

int main(int argc, char *argv[]) {
    pid_t pid = fork();
    if (pid == -1) {
        return 1;
    } else if (pid == 0) {
        hijo();
    } else {
        padre(pid);
    }
    return 0;
}