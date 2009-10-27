;;; -*- mode: emacs-lisp; indent-tabs-mode: nil -*-
(if (not noninteractive)
    (error "to be used only with -batch"))
;; Avoid vc-mode interference.
(setq vc-handled-backends nil)
(while command-line-args-left
  (let ((filename (car command-line-args-left))
        (error nil)
        ;; No backup files?
        (make-backup-files nil))
    (find-file filename)

    ;; (goto-char (point-min))
    ;; (if (looking-at "\\s-*/\\*\\s-*-\\*-.*-\\*-\\s-*\\*/\\s-*\n")
    ;;  (delete-region (match-beginning 0) (match-end 0)))
    ;; (insert "/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */\n")
    ;; (normal-mode)

    (if (eq indent-tabs-mode nil)
        (untabify (point-min) (point-max)))

    ;; Only reindent if the file C style is guessed to be "krb5".
    (if (and (eq c-basic-offset 4)
             (eq indent-tabs-mode nil))
        (progn
          (c-set-style "krb5")
          (c-indent-region (point-min) (point-max))))

    (whitespace-cleanup)

    (save-buffer)
    (kill-buffer)
    (setq command-line-args-left (cdr command-line-args-left))))
