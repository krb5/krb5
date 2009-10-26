;;; -*- mode: emacs-lisp; indent-tabs-mode: nil -*-
(defconst krb5-c-style
  '("bsd"
    (c-basic-offset     . 4)
    (c-cleanup-list     . (brace-elseif-brace
                           brace-else-brace
                           defun-close-semi))
    (c-comment-continuation-stars       . "* ")
    (c-comment-only-line-offset . 0)
    (c-electric-pound-behavior  . (alignleft))
    (c-hanging-braces-alist     . ((block-close . c-snug-do-while)
                                   (brace-list-open)
                                   (class-open after)
                                   (extern-lang-open after)
                                   (substatement-open after)))
    (c-hanging-colons-alist     . ((case-label after)
                                   (label after)))
    (c-hanging-comment-starter-p        . nil)
    (c-hanging-comment-ender-p          . nil)
    (c-indent-comments-syntactically-p  . t)
    (c-label-minimum-indentation        . 0)
    (c-offsets-alist    . ((inextern-lang . 0)
                           (arglist-close . 0)))
    (c-special-indent-hook      . nil)
    (fill-column                . 79)))

(defun krb5-c-hook ()
  (c-add-style "krb5" krb5-c-style))

(add-hook 'c-initialization-hook 'krb5-c-hook)
