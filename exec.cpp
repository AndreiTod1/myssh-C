#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

using namespace std;

struct Command {
    vector<string> args;
    string input_redirection;
    string output_redirection;
    string error_redirection;
    string operator_after;
};

string eroare;

bool is_operator(const string &token) {
    return token == "|" || token == "&&" || token == "||" || token == ";";
}

vector<string> tokenize(string command) {
    vector<string> tokens;
    string current_token = "";
    bool in_single = false;
    bool in_double = false;

    for (size_t i = 0; i < command.length(); i++) {
        char c = command[i];

        if (c == '\'' && !in_double) {
            in_single = !in_single;
            continue;
        }
        if (c == '"' && !in_single) {
            in_double = !in_double;
            continue;
        }

        if (in_single || in_double) {
            current_token += c;
            continue;
        }

        if (c == ' ') {
            if (!current_token.empty()) {
                tokens.push_back(current_token);
                current_token = "";
            }
            continue;
        }

        if (c == '&') {
            if (i + 1 < command.length() && command[i + 1] == '&') {
                if (!current_token.empty()) {
                    tokens.push_back(current_token);
                    current_token = "";
                }
                tokens.push_back("&&");
                i++;
                continue;
            }
        }
        if (c == '|') {
            if (i + 1 < command.length() && command[i + 1] == '|') {
                if (!current_token.empty()) {
                    tokens.push_back(current_token);
                    current_token = "";
                }
                tokens.push_back("||");
                i++;
                continue;
            } else {
                if (!current_token.empty()) {
                    tokens.push_back(current_token);
                    current_token = "";
                }
                tokens.push_back("|");
                continue;
            }
        }
        if (c == ';') {
            if (!current_token.empty()) {
                tokens.push_back(current_token);
                current_token = "";
            }
            tokens.push_back(";");
            continue;
        }
        if (c == '>') {
            if (i + 1 < command.length() && command[i + 1] == '>') {
                if (!current_token.empty()) {
                    tokens.push_back(current_token);
                    current_token = "";
                }
                tokens.push_back(">>");
                i++;
                continue;
            }
            if (i + 1 < command.length() && command[i + 1] == '2') {
                if (!current_token.empty()) {
                    tokens.push_back(current_token);
                    current_token = "";
                }
                tokens.push_back("2>");
                i++;
                continue;
            }
            if (!current_token.empty()) {
                tokens.push_back(current_token);
                current_token = "";
            }
            tokens.push_back(">");
            continue;
        }
        if (c == '2') {
            if (i + 1 < command.length() && command[i + 1] == '>') {
                if (!current_token.empty()) {
                    tokens.push_back(current_token);
                    current_token = "";
                }
                tokens.push_back("2>");
                i++;
                continue;
            }
        }

        current_token += c;
    }

    if (!current_token.empty()) {
        tokens.push_back(current_token);
    }

    return tokens;
}

vector<Command> parse_commands(string command) {
    vector<Command> commands;
    vector<string> tokens = tokenize(command);

    if (!tokens.empty() && is_operator(tokens[0])) {
        eroare = "[EROARE] Comanda nu poate începe cu un operator: " + tokens[0];
        return commands;
    }

    if (!tokens.empty() && (tokens.back() == "|" ||
                            tokens.back() == "&&" ||
                            tokens.back() == "||")) {
        eroare = "[EROARE] Comanda se termină cu operator: " + tokens.back();
        return commands;
    }
    
    for (size_t i = 0; i + 1 < tokens.size(); i++) {
        if (is_operator(tokens[i]) && is_operator(tokens[i + 1])) {
            eroare = "[EROARE] S-au găsit 2 operatori consecutivi: " + tokens[i] + " " + tokens[i + 1];
            return commands;
        }
    }
    
    Command current_command;
    size_t i = 0;
    while (i < tokens.size()) {
        string token = tokens[i];
        if (token == "<") {
            if (i + 1 < tokens.size()) {
                if (is_operator(tokens[i + 1])) {
                    eroare = "[EROARE] Redirectionare intrare fără fișier; următorul operator: " + tokens[i + 1];
                    return commands;
                }
                current_command.input_redirection = tokens[i + 1];
                i++;
            } else {
                eroare = "[EROARE] Redirectionare intrare fără fișier.\n";
                return commands;
            }
        }
        else if (token == ">") {
            if (i + 1 < tokens.size()) {
                if (is_operator(tokens[i + 1])) {
                    eroare = "[EROARE] Redirectionare ieșire fără fișier; următorul operator: " + tokens[i + 1];
                    return commands;
                }
                current_command.output_redirection = tokens[i + 1];
                i++;
            }
            else {
                eroare = "[EROARE] Redirectionare ieșire fără fișier.\n";
                return commands;
            }
        }
        else if (token == "2>") {
            if (i + 1 < tokens.size()) {
                if (is_operator(tokens[i + 1])) {
                    eroare = "[EROARE] Redirectionare eroare fără fișier; următorul operator: " + tokens[i + 1];
                    return commands;
                }
                current_command.error_redirection = tokens[i + 1];
                i++;
            }
            else {
                eroare = "[EROARE] Redirectionare eroare fără fișier.\n";
                return commands;
            }
        }
        else if (is_operator(token)) {
            current_command.operator_after = token;
            commands.push_back(current_command);
            current_command = Command();
        }
        else {
            current_command.args.push_back(token);
        }
        i++;
    }
    if (!current_command.args.empty() || !current_command.operator_after.empty()) {
        commands.push_back(current_command);
    }
    return commands;
}

bool execute_internal_command(Command cmd, int &status, int out_fd, int err_fd, int client_id, vector<string> &paths)
{
    if (cmd.args.empty()) return false;

    int original_stdout = dup(STDOUT_FILENO);
    int original_stderr = dup(STDERR_FILENO);

    dup2(out_fd, STDOUT_FILENO);
    dup2(err_fd, STDERR_FILENO);

    bool handled = false;
    if (cmd.args[0] == "cd") {
        if (cmd.args.size() < 2) {
            printf("cd: nu s-a dat argument\n");
            status = 1;
        } else {
            string new_path = cmd.args[1];
            if (new_path[0] != '/') {
                new_path = paths[client_id] + "/" + new_path;
            }
            char resolved_path[1024];
            if (realpath(new_path.c_str(), resolved_path) == NULL) {
                perror("cd");
                status = 1;
            } else {
                paths[client_id] = string(resolved_path);
                status = 0;
                printf("Directorul curent schimbat la: %s\n", paths[client_id].c_str());
            }
        }
        handled = true;
    }

    dup2(original_stdout, STDOUT_FILENO);
    dup2(original_stderr, STDERR_FILENO);
    close(original_stdout);
    close(original_stderr);
    return handled;
}

pid_t execute_external_command(Command cmd, int input_fd, int output_fd, int error_fd, int client_id, vector<string> &paths)
{
    pid_t pid = fork();
    if (pid == 0) {
        if (chdir(paths[client_id].c_str()) != 0) {
            perror("chdir");
            exit(EXIT_FAILURE);
        }
        if (input_fd != STDIN_FILENO) {
            dup2(input_fd, STDIN_FILENO);
            close(input_fd);
        }

        if (output_fd != STDOUT_FILENO) {
            dup2(output_fd, STDOUT_FILENO);
            if (output_fd != error_fd) {
                close(output_fd);
            }
        }
        if (error_fd != STDERR_FILENO) {
            dup2(error_fd, STDERR_FILENO);
            if (error_fd != output_fd) {
                close(error_fd);
            }
        }
        setbuf(stdout, NULL);
        setbuf(stderr, NULL);

        vector<char*> argv;
        for (auto &arg : cmd.args) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(NULL);

        execvp(argv[0], argv.data());
        perror("execvp");
        fflush(stderr);
        exit(EXIT_FAILURE);
    } else if (pid < 0) {
        perror("fork");
        return -1;
    }
    return pid;
}
string execute_commands(vector<Command> commands, int client_id, vector<string> &paths) {
    int num_cmds = commands.size();
    int input_fd = STDIN_FILENO;
    int status = 0;
    int pipe_fd[2];
    int capture_pipe[2];
    if (pipe(capture_pipe) == -1) {
        perror("pipe");
        return "";
    }
    
    string output_data;

    for (int i = 0; i < num_cmds; i++) {
        Command cmd = commands[i];

        if (i > 0) {
            string prev_operator = commands[i - 1].operator_after;
            if (prev_operator == "&&" && status != 0)
                continue;
            if (prev_operator == "||" && status == 0)
                continue;
        }

        bool has_pipe = false;
        if (cmd.operator_after == "|") {
            has_pipe = true;
            if (pipe(pipe_fd) < 0) {
                perror("pipe");
                return "";
            }
        }

        int out_fd, err_fd;
        if (!cmd.output_redirection.empty()) {
            out_fd = open(cmd.output_redirection.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (out_fd < 0) {
                perror("open output redirection");
                return "";
            }
        } else {
            if ( has_pipe) 
                out_fd = pipe_fd[1];
            else out_fd = capture_pipe[1];
        }
        if (!cmd.error_redirection.empty()) {
            err_fd = open(cmd.error_redirection.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (err_fd < 0) {
                perror("open error redirection");
                return "";
            }
        } else {
            if (!cmd.output_redirection.empty()) {
                err_fd = capture_pipe[1];
            } else {
                err_fd = out_fd;
            }
        }

        if (!cmd.input_redirection.empty()) {
            input_fd = open(cmd.input_redirection.c_str(), O_RDONLY);
            if (input_fd < 0) {
                perror("open input redirection");
                return "";
            }
        }

        bool is_internal = execute_internal_command(cmd, status, out_fd, err_fd, client_id, paths);
        if (!is_internal) {
            pid_t pid = execute_external_command(cmd, input_fd, out_fd, err_fd, client_id, paths);
            if (pid < 0) {
                printf("Eroare la executia comenzii.\n");
                return "";
            }
            waitpid(pid, &status, 0);
        }

        if (!cmd.output_redirection.empty() && !has_pipe)
            close(out_fd);
        if (!cmd.error_redirection.empty() && !has_pipe)
            close(err_fd);

        if (has_pipe) {
            close(pipe_fd[1]);
            input_fd = pipe_fd[0];
        } else {
            input_fd = STDIN_FILENO;
        }
    }
    close(capture_pipe[1]);

    {
        char buffer[4096];
        ssize_t count;
        while ((count = read(capture_pipe[0], buffer, sizeof(buffer))) > 0) {
            output_data.append(buffer, count);
        }
        close(capture_pipe[0]);
    }
    if (output_data.empty() && status == 0)
        output_data = "success";
    return output_data;
}

string execution(string input, int client_id, vector<string> &paths) {
    string output;
    eroare.clear();
    if (input.empty()) {
        printf("Empty input.\n");
        return "";
    }
    vector<Command> commands = parse_commands(input);
    if (commands.empty())
        return eroare;
    if (commands[0].args[0] == "exit")
        return "exit";
    output = execute_commands(commands, client_id, paths);
    return output;
}


