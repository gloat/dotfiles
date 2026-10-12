# gloat's config.fish 2026

if status is-interactive
    # Commands to run in interactive sessions can go here
end

set -e fish_user_paths
set -U fish_user_paths $HOME/.bin $fish_user_paths
set -U fish_user_paths /usr/local/openresty/bin $fish_user_paths

set fish_greeting
set -gx FZF_DEFAULT_OPTS "--layout=reverse --exact --border=bold --border=rounded --margin=3% --color=dark"
set -gx PATH "/home/gloat/.local/bin" $PATH
set -x MANPAGER less

set fish_color_normal brcyan
set fish_color_autosuggestion '#7d7d7d'
set fish_color_command brcyan
set fish_color_error '#ff6c6b'
set fish_color_param brcyan

alias ls='eza -al --color=always --icons --group-directories-first' # my preferred listing

#alias ls='eza --classify=auto --color --group-directories-first --sort=extension -A'
alias la='eza --classify=auto --color --group-directories-first --sort=extension -a -l --octal-permissions --no-permissions'

# ps
alias psa="ps auxf"
alias psgrep="ps aux | grep -v grep | grep -i -e VSZ -e"
alias psmem='ps auxf | sort -nr -k 4'
alias pscpu='ps auxf | sort -nr -k 3'

abbr mv 'mv -v'
abbr rm 'rm -v'
abbr cp 'cp -v'
abbr cat 'bat -P'

# adding flags
alias df='df -h' # human-readable sizes
alias free='free -m' # show sizes in MB
alias grep='grep --color=auto' # colorize output (good for log files)

fzf --fish | source

#shortcuts
alias cdergo="cd /var/lib/ergo"
alias html="cd /usr/share/nginx/html"
alias cdnginx "cd /usr/local/openresty/nginx/"
