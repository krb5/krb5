;;; -*- mode: emacs-lisp; indent-tabs-mode: nil -*-
(if (not noninteractive)
    (error "to be used only with -batch"))

(defvar bsd-style nil)
(defvar krb5-style nil)

(push '("-cstyle-bsd" . (lambda (ignored) (setq bsd-style t))) command-switch-alist)
(push '("-cstyle-krb5" . (lambda (ignored) (setq krb5-style t))) command-switch-alist)

;; Avoid vc-mode interference.
(setq vc-handled-backends nil)
(while command-line-args-left
  (let ((filename (car command-line-args-left))
        (error nil)
        ;; No backup files?
        (make-backup-files nil))
    (find-file filename)

    (goto-char (point-min))
    (if (looking-at "\\s-*/\\*\\s-*-\\*-.*-\\*-\\s-*\\*/\\s-*\n")
     (delete-region (match-beginning 0) (match-end 0)))
    (if bsd-style
        (insert "/* -*- mode: c; c-file-style: \"bsd\"; indent-tabs-mode: t -*- */\n")
      (insert "/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */\n"))
    (save-buffer)
    (kill-buffer)
    (setq command-line-args-left (cdr command-line-args-left))))
