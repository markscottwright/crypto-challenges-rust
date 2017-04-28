use bytes::{inplace_xor, repeat_xor};
use crypto::{symmetriccipher, buffer, aes, blockmodes};
use crypto::buffer::{BufferResult, WriteBuffer, ReadBuffer};

pub fn encrypt_ecb(data: &[u8],
                   key: &[u8])
                   -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    if key.len() * 8 != 128 {
        return Err(symmetriccipher::SymmetricCipherError::InvalidLength);
    }

    let keysize = aes::KeySize::KeySize128;

    let mut encryptor = aes::ecb_encryptor(keysize, key, blockmodes::NoPadding);

    // Each encryption operation encrypts some data from
    // an input buffer into an output buffer. Those buffers
    // must be instances of RefReaderBuffer and RefWriteBuffer
    // (respectively) which keep track of how much data has been
    // read from or written to them.
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    // Each encryption operation will "make progress". "Making progress"
    // is a bit loosely defined, but basically, at the end of each operation
    // either BufferUnderflow or BufferOverflow will be returned (unless
    // there was an error). If the return value is BufferUnderflow, it means
    // that the operation ended while wanting more input data. If the return
    // value is BufferOverflow, it means that the operation ended because it
    // needed more space to output data. As long as the next call to the encryption
    // operation provides the space that was requested (either more input data
    // or more output space), the operation is guaranteed to get closer to
    // completing the full operation - ie: "make progress".
    //
    // Here, we pass the data to encrypt to the enryptor along with a fixed-size
    // output buffer. The 'true' flag indicates that the end of the data that
    // is to be encrypted is included in the input buffer (which is true, since
    // the input data includes all the data to encrypt). After each call, we copy
    // any output data to our result Vec. If we get a BufferOverflow, we keep
    // going in the loop since it means that there is more work to do. We can
    // complete as soon as we get a BufferUnderflow since the encryptor is telling
    // us that it stopped processing data due to not having any more data in the
    // input buffer.
    loop {
        let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));

        // "write_buffer.take_read_buffer().take_remaining()" means:
        // from the writable buffer, create a new readable buffer which
        // contains all data that has been written, and then access all
        // of that data as a slice.
        final_result.extend(write_buffer
                                .take_read_buffer()
                                .take_remaining()
                                .iter()
                                .map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

// Decrypts a buffer with the given key and iv using
// AES-256/CBC/Pkcs encryption.
//
// This function is very similar to encrypt(), so, please reference
// comments in that function. In non-example code, if desired, it is possible to
// share much of the implementation using closures to hide the operation
// being performed. However, such code would make this example less clear.
pub fn decrypt_ecb(encrypted_data: &[u8],
                   key: &[u8])
                   -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    if key.len() * 8 != 128 {
        return Err(symmetriccipher::SymmetricCipherError::InvalidLength);
    }
    let keysize = aes::KeySize::KeySize128;

    let mut decryptor = aes::ecb_decryptor(keysize, key, blockmodes::NoPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer
                                .take_read_buffer()
                                .take_remaining()
                                .iter()
                                .map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

pub fn decrypt_cbc(ciphertext: &[u8],
                   key: &[u8],
                   iv: &[u8])
                   -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    assert_eq!(key.len(), iv.len());
    let mut cleartext = Vec::with_capacity(ciphertext.len());
    let mut chunks = ciphertext.chunks(key.len());

    match chunks.next() {
        Some(c) => {
            assert_eq!(c.len(), key.len());
            // do the first block
            let mut block = try!(decrypt_ecb(c, key));
            block = inplace_xor(block, iv);
            cleartext.extend_from_slice(&block);
            let mut last_block = c;

            // do the rest of the blocks
            for c in chunks {
                assert_eq!(c.len(), key.len());
                let mut block = try!(decrypt_ecb(c, key));
                block = inplace_xor(block, &last_block);
                cleartext.extend_from_slice(&block);
                last_block = c;
            }

            Ok(cleartext)
        }
        None => Ok(cleartext),
    }
}

pub fn encrypt_cbc(cleartext: &[u8],
                   key: &[u8],
                   iv: &[u8])
                   -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    assert_eq!(key.len(), iv.len());
    let mut ciphertext = Vec::with_capacity(cleartext.len());
    let mut chunks = cleartext.chunks(key.len());

    match chunks.next() {
        Some(c) => {
            assert_eq!(c.len(), key.len());
            // do the first block
            let mut block = repeat_xor(c, iv);
            // TODO - there's an extra alloc here - we could have an inplace
            // encrypt ecb
            block = try!(encrypt_ecb(&block, key));
            ciphertext.extend_from_slice(&block);
            let mut last_block = block;

            // do the rest of the blocks
            for c in chunks {
                assert_eq!(c.len(), key.len());
                let mut block = repeat_xor(c, &last_block);
                block = try!(encrypt_ecb(&block, key));
                ciphertext.extend_from_slice(&block);
                last_block = block;
            }

            Ok(ciphertext)
        }
        None => Ok(ciphertext),
    }
}

#[test]
fn test() {
    let data = b"yellow submarine";
    let key = b"1234567812345678";
    let encrypted = encrypt_ecb(data, key).unwrap();
    let decrypted = decrypt_ecb(&encrypted, key).unwrap();
    assert_eq!(data, decrypted.as_slice());
}

#[test]
fn test_mirror() {
    let data = b"yellow submarine1234567812345678";
    let key = b"1234567812345678";

    let encrypted = encrypt_cbc(data, key, &[0u8; 16]).unwrap();
    let decrypted = decrypt_cbc(&encrypted, key, &[0u8; 16]).unwrap();
    assert_eq!(data, decrypted.as_slice());
}
