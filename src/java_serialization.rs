//! Skips one Java serialization stream without deserializing it. JCEKS stores
//! each secret key as a serialized `SealedObject` with no length prefix, so the
//! only way to find the next entry is to walk the stream's grammar. Nothing is
//! decrypted, and no class is ever loaded or interpreted beyond its layout.

const STREAM_MAGIC: [u8; 2] = [0xac, 0xed];
const STREAM_VERSION: [u8; 2] = [0x00, 0x05];
const TC_NULL: u8 = 0x70;
const TC_REFERENCE: u8 = 0x71;
const TC_CLASSDESC: u8 = 0x72;
const TC_OBJECT: u8 = 0x73;
const TC_STRING: u8 = 0x74;
const TC_ARRAY: u8 = 0x75;
const TC_BLOCKDATA: u8 = 0x77;
const TC_ENDBLOCKDATA: u8 = 0x78;
const TC_BLOCKDATALONG: u8 = 0x7a;
const TC_LONGSTRING: u8 = 0x7c;
const BASE_HANDLE: u32 = 0x7e_0000;
const SC_WRITE_METHOD: u8 = 0x01;
const SC_SERIALIZABLE: u8 = 0x02;
const SC_EXTERNALIZABLE: u8 = 0x04;
/// Nesting deeper than this is refused, so hostile input cannot exhaust the stack.
const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Truncated,
    Invalid,
    Unsupported,
}

/// A class layout. `super_class` is `None` until the descriptor is complete,
/// which also stops a class from (indirectly) extending itself.
struct ClassDesc {
    name: Vec<u8>,
    flags: u8,
    /// The type code of each serializable field, in stream order.
    fields: Vec<u8>,
    super_class: Option<Option<usize>>,
}

enum Handle {
    Class(usize),
    Other,
}

struct Stream<'a> {
    remaining: &'a [u8],
    classes: Vec<ClassDesc>,
    handles: Vec<Handle>,
}

/// Skips one serialization stream holding a single top-level object, returning
/// that object's class name and the data after the stream.
pub fn skip_object(data: &[u8]) -> Result<(Vec<u8>, &[u8]), Error> {
    let mut stream = Stream {
        remaining: data,
        classes: Vec::new(),
        handles: Vec::new(),
    };
    if stream.take(2)? != STREAM_MAGIC || stream.take(2)? != STREAM_VERSION {
        return Err(Error::Invalid);
    }
    if stream.u8()? != TC_OBJECT {
        return Err(Error::Unsupported);
    }
    let class = stream.object(0)?;
    Ok((
        std::mem::take(&mut stream.classes[class].name),
        stream.remaining,
    ))
}

impl<'a> Stream<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        if len > self.remaining.len() {
            return Err(Error::Truncated);
        }
        let (bytes, remaining) = self.remaining.split_at(len);
        self.remaining = remaining;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn utf(&mut self) -> Result<&'a [u8], Error> {
        let len = self.u16()?;
        self.take(usize::from(len))
    }

    /// Reads a handle and returns the class it refers to, if it is one.
    fn handle(&mut self) -> Result<Option<usize>, Error> {
        let index = self.u32()?.checked_sub(BASE_HANDLE).ok_or(Error::Invalid)?;
        match self.handles.get(index as usize).ok_or(Error::Invalid)? {
            Handle::Class(class) => Ok(Some(*class)),
            Handle::Other => Ok(None),
        }
    }

    /// Any content element, by its already-read type code.
    fn content(&mut self, code: u8, depth: usize) -> Result<(), Error> {
        if depth > MAX_DEPTH {
            return Err(Error::Unsupported);
        }
        match code {
            TC_NULL => {}
            TC_REFERENCE => {
                self.handle()?;
            }
            TC_STRING => {
                self.handles.push(Handle::Other);
                self.utf()?;
            }
            TC_LONGSTRING => {
                self.handles.push(Handle::Other);
                let len = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
                self.take(usize::try_from(len).map_err(|_| Error::Truncated)?)?;
            }
            TC_CLASSDESC => {
                self.new_class(depth)?;
            }
            TC_OBJECT => {
                self.object(depth)?;
            }
            TC_ARRAY => self.array(depth)?,
            TC_BLOCKDATA => {
                let len = self.u8()?;
                self.take(usize::from(len))?;
            }
            TC_BLOCKDATALONG => {
                let len = self.u32()?;
                self.take(len as usize)?;
            }
            // Enums, classes, proxies, resets and exceptions never appear in
            // the sealed keys Java writes.
            _ => return Err(Error::Unsupported),
        }
        Ok(())
    }

    /// A class descriptor: a new one, a reference to a complete one, or null.
    fn class_desc(&mut self, depth: usize) -> Result<Option<usize>, Error> {
        match self.u8()? {
            TC_NULL => Ok(None),
            TC_CLASSDESC => self.new_class(depth).map(Some),
            TC_REFERENCE => match self.handle()? {
                Some(index) if self.classes[index].super_class.is_some() => Ok(Some(index)),
                _ => Err(Error::Invalid),
            },
            _ => Err(Error::Unsupported),
        }
    }

    fn new_class(&mut self, depth: usize) -> Result<usize, Error> {
        let name = self.utf()?.to_vec();
        self.take(8)?; // serialVersionUID.
        let index = self.classes.len();
        self.handles.push(Handle::Class(index));
        let flags = self.u8()?;
        let count = self.u16()?;
        let mut fields = Vec::new();
        for _ in 0..count {
            let code = self.u8()?;
            self.utf()?; // Field name.
            if matches!(code, b'[' | b'L') {
                // The field's class name, as a string or a reference to one.
                let code = self.u8()?;
                if !matches!(code, TC_STRING | TC_LONGSTRING | TC_REFERENCE) {
                    return Err(Error::Invalid);
                }
                self.content(code, depth + 1)?;
            } else if field_size(code).is_none() {
                return Err(Error::Invalid);
            }
            fields.push(code);
        }
        self.classes.push(ClassDesc {
            name,
            flags,
            fields,
            super_class: None,
        });
        self.annotation(depth)?;
        let super_class = self.class_desc(depth + 1)?;
        self.classes[index].super_class = Some(super_class);
        Ok(index)
    }

    /// Contents written by a class's own write method, up to its end marker.
    fn annotation(&mut self, depth: usize) -> Result<(), Error> {
        loop {
            match self.u8()? {
                TC_ENDBLOCKDATA => return Ok(()),
                code => self.content(code, depth + 1)?,
            }
        }
    }

    /// An object's class and field values. Returns its class.
    fn object(&mut self, depth: usize) -> Result<usize, Error> {
        let class = self.class_desc(depth + 1)?.ok_or(Error::Invalid)?;
        self.handles.push(Handle::Other);
        // Superclass data comes first. Complete descriptors only point to
        // earlier complete ones, so this walk ends.
        let mut hierarchy = vec![class];
        while let Some(Some(parent)) = self.classes[hierarchy[hierarchy.len() - 1]].super_class {
            hierarchy.push(parent);
        }
        for &index in hierarchy.iter().rev() {
            let flags = self.classes[index].flags;
            if flags & SC_EXTERNALIZABLE != 0 {
                return Err(Error::Unsupported);
            }
            if flags & SC_SERIALIZABLE == 0 {
                continue;
            }
            for field in 0..self.classes[index].fields.len() {
                let code = self.classes[index].fields[field];
                self.value(code, depth + 1)?;
            }
            if flags & SC_WRITE_METHOD != 0 {
                self.annotation(depth)?;
            }
        }
        Ok(class)
    }

    fn array(&mut self, depth: usize) -> Result<(), Error> {
        let class = self.class_desc(depth + 1)?.ok_or(Error::Invalid)?;
        self.handles.push(Handle::Other);
        let element = match self.classes[class].name.as_slice() {
            [b'[', code, ..] => *code,
            _ => return Err(Error::Invalid),
        };
        let len = self.u32()?;
        if let Some(size) = field_size(element) {
            let bytes = (len as usize).checked_mul(size).ok_or(Error::Truncated)?;
            self.take(bytes)?;
        } else {
            // Every element takes at least one byte, so a huge count runs out of data.
            for _ in 0..len {
                self.value(element, depth + 1)?;
            }
        }
        Ok(())
    }

    fn value(&mut self, code: u8, depth: usize) -> Result<(), Error> {
        match field_size(code) {
            Some(size) => self.take(size).map(drop),
            None if matches!(code, b'[' | b'L') => {
                let code = self.u8()?;
                self.content(code, depth)
            }
            None => Err(Error::Invalid),
        }
    }
}

/// The size of a primitive field, or `None` for objects and unknown codes.
fn field_size(code: u8) -> Option<usize> {
    match code {
        b'B' | b'Z' => Some(1),
        b'C' | b'S' => Some(2),
        b'I' | b'F' => Some(4),
        b'J' | b'D' => Some(8),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::sealed_secret_key;

    #[test]
    fn skips_a_sealed_key_in_the_layout_java_writes() {
        let mut data = sealed_secret_key();
        data.extend_from_slice(b"next");
        let (class, rest) = skip_object(&data).unwrap();
        assert_eq!(
            class,
            b"com.sun.crypto.provider.SealedObjectForKeyProtector"
        );
        assert_eq!(rest, b"next");
    }

    #[test]
    fn rejects_every_truncated_prefix() {
        let data = sealed_secret_key();
        for end in 0..data.len() {
            assert!(skip_object(&data[..end]).is_err(), "prefix {end}");
        }
    }

    #[test]
    fn rejects_bad_headers_references_and_unsupported_content() {
        let mut header = STREAM_MAGIC.to_vec();
        header.extend_from_slice(&STREAM_VERSION);
        for (body, error) in [
            (&[TC_STRING, 0, 0][..], Error::Unsupported),
            (&[TC_OBJECT, TC_NULL], Error::Invalid),
            // A reference to a handle that does not exist yet.
            (&[TC_OBJECT, TC_REFERENCE, 0, 0x7e, 0, 0], Error::Invalid),
            (&[TC_OBJECT, 0x7e], Error::Unsupported),
        ] {
            let data = [header.as_slice(), body].concat();
            assert_eq!(skip_object(&data), Err(error), "{body:?}");
        }
        assert_eq!(skip_object(b"\xac\xed\x00\x04"), Err(Error::Invalid));
    }

    #[test]
    fn a_class_cannot_extend_itself() {
        let mut data = vec![0xac, 0xed, 0, 5, TC_OBJECT, TC_CLASSDESC, 0, 1, b'A'];
        data.extend_from_slice(&[0; 8]); // serialVersionUID.
        data.extend_from_slice(&[SC_SERIALIZABLE, 0, 0, TC_ENDBLOCKDATA]);
        // The superclass refers back to the descriptor being read.
        data.extend_from_slice(&[TC_REFERENCE, 0, 0x7e, 0, 0]);
        assert_eq!(skip_object(&data), Err(Error::Invalid));
    }

    #[test]
    fn refuses_deep_nesting() {
        // An Object[] array of Object[] arrays, nested far beyond the limit.
        let mut data = vec![0xac, 0xed, 0, 5, TC_OBJECT, TC_CLASSDESC, 0, 1, b'A'];
        data.extend_from_slice(&[0; 8]);
        data.extend_from_slice(&[
            SC_SERIALIZABLE,
            0,
            1,
            b'L',
            0,
            1,
            b'f',
            TC_STRING,
            0,
            1,
            b'X',
        ]);
        data.extend_from_slice(&[TC_ENDBLOCKDATA, TC_NULL]);
        data.extend_from_slice(&[TC_ARRAY, TC_CLASSDESC, 0, 2, b'[', b'L']);
        data.extend_from_slice(&[0; 8]);
        data.extend_from_slice(&[SC_SERIALIZABLE, 0, 0, TC_ENDBLOCKDATA, TC_NULL, 0, 0, 0, 1]);
        for _ in 0..100 {
            data.extend_from_slice(&[TC_ARRAY, TC_REFERENCE, 0, 0x7e, 0, 3, 0, 0, 0, 1]);
        }
        assert_eq!(skip_object(&data), Err(Error::Unsupported));
    }
}
