(ql:quickload "ironclad")
(in-package :ironclad)
(defun read-from-file (file-name)
  (let ((file-contents ""))
    (with-open-file (in file-name :if-does-not-exist nil)
      (loop for line = (read-line in nil nil )
	 while line
	 do (setq file-contents (concatenate 'string file-contents line
					     ;; removes newline
					     ))))
    file-contents))
(defun sign-file-contents (file-name private-key)
  "returns the signature of the contents of the file FILE-NAME based on the key PRIVATE-KEY"
  (let ((file-contents (read-from-file file-name)))
    (sign-message private-key (ascii-string-to-byte-array file-contents))))

(defun verify-signed-message (public-key signature string-or-identifier &optional (is-file nil) )
  (if is-file
      (setq string-or-identifier (read-from-file string-or-identifier)))
  (verify-signature public-key string-or-identifier signature ))

(defun gen-key-pair (num-bits)
  (multiple-value-list (generate-key-pair :RSA :num-bits num-bits)))

(let* ((keypair (gen-key-pair 2048))
       (file-name "test-data")
       (pri (first keypair))
       (pub (second keypair))
       (signed-data (sign-file-contents file-name pri)))
  (verify-signature pub signed-data file-name))
