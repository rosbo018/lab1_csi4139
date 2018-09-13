(ql:quickload "ironclad")
(in-package :ironclad)

(defun read-from-file (filename)
  (with-open-file (stream filename)
    (let ((contents (make-string (file-length stream))))
      (read-sequence contents stream)
      (ascii-string-to-byte-array contents))))

(defun sign-data (data private-key)
  "returns the signature of the contents of the file FILE-NAME based on the key PRIVATE-KEY"
  (sign-message private-key data))

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

(defun encrypt-data (public-key data)
  (encrypt-message public-key data))
(defun decrypt-data (private-key encrypted-data)
   (decrypt-message private-key encrypted-data))

(defun ascii-to-string (ascii-vector)
  (let ((result (make-array 0 :element-type 'character :fill-pointer 0 :adjustable t)))
    (loop
       for i across ascii-vector
       do (vector-push-extend (code-char i)  result))
    result))

(let* ((file-name "test-data")
       (keypair (gen-key-pair 2048))
       (pri (first keypair))
       (pub (second keypair))
       (encrypted-data (encrypt-file pub file-name)))
  (ascii-to-string (decrypt-message pri encrypted-data)))

(defun hash-data (data)
    (let* ((digest (make-digest :sha256)))
      (update-digest digest data)
      (produce-digest digest)))

(defun part1 (file-name)
  (let* ((pair1 (gen-key-pair 512))
	 (pair2 (gen-key-pair 512))
	 (data (read-from-file file-name))
	 (hash (hash-data data))
	 (signed-data (sign-data hash (first pair1)))

	 (encrypted-data (encrypt-data (second pair2) data ))
	 (decrypted-data (decrypt-data (first pair2) encrypted-data)))
    (and (verify-signature (second pair1) hash signed-data)
    	 (equalp data decrypted-data))))
(part1 "test-data")


