/*
 * memprocfs_packager
 * 
 * Copyright (C) 2024  Sleuth Kit Labs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.sleuthkitlabs.memprocfspackager;

import java.io.IOException;
import java.io.InputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import vmm.IVmm;
import vmm.VmmException;

public class VFSInputStream extends InputStream {

    private static final Logger LOGGER = LoggerFactory.getLogger(VFSInputStream.class);

    private static final int CHUNK_SIZE = 1024;

    private final String file;
    private final IVmm vmm;
    private final int size;
    private int offset = 0;
    private byte[] buffer;
    private int bufferPos = 0;
    private int bufferLimit = 0;
    private int bytesRead = 0;

    public VFSInputStream(String file, int size, IVmm vmm) {
        this.file = file;
        this.size = size;
        this.vmm = vmm;
    }

    @Override
    public int read() throws IOException {

        if (bytesRead >= size) {
            return -1; // End of stream
        }

        if (bufferPos >= bufferLimit) {
            loadNextChunk();
            if (bufferLimit == -1) {
                return -1; // End of stream
            }
        }

        bytesRead++;
        return buffer[bufferPos++] & 0xFF; // Return the next byte as unsigned int
    }

    private void loadNextChunk() throws IOException {

        int remaining = size - bytesRead;
        int sizeToRead = Math.min(remaining, CHUNK_SIZE);

        byte[] bytes = null;
        try {
            bytes = vmm.vfsRead(file, offset, sizeToRead);
        } catch (VmmException ex) {
            LOGGER.error("Error reading file " + file + " : ", ex);
        }

        if (bytes == null || bytes.length == 0) {
            bufferLimit = -1; // End of file reached
            return;
        }

        // Convert the chunk data to bytes
        buffer = bytes;
        bufferPos = 0;
        bufferLimit = buffer.length;
        offset += bufferLimit; // Update the offset for the next read
    }
}