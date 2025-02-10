/*
 * libcdoc
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

package ee.ria.cdoc;

import java.io.IOException;
import java.io.InputStream;
import java.io.BufferedInputStream;

public class IStreamSource extends DataSource {
    private InputStream ifs;

    public IStreamSource(InputStream ifs) {
        if (ifs.markSupported()) {
            this.ifs = ifs;
        } else {
            this.ifs = new BufferedInputStream(ifs, 100000000);
        }
        this.ifs.mark(100000000);
    }

    @Override
    public int seek(long pos) {
        System.err.format("IStreamSource: seek(%d)\n", pos);
        try {
            ifs.reset();
            long nskipped = 0;
            while (nskipped < pos) {
                nskipped += ifs.skip(pos - nskipped);
            }
        } catch (IOException exc) {
            System.err.format("IStreamSource: seek - exception: %s\n", exc.getMessage());
            return CDoc.INPUT_STREAM_ERROR;
        }
        return CDoc.OK;
    }
    
    public long read(byte[] dst) {
        System.err.format("IStreamSource: read([%d])\n", dst.length);
        try {
            int nread = 0;
            while (nread < dst.length) {
                int val = ifs.read(dst, nread, dst.length - nread);
                if (val < 0) return nread;
                nread += val;
            }
            return nread;
        } catch (IOException exc) {
            System.err.format("IStreamSource: read - exception: %s\n", exc.getMessage());
            return CDoc.INPUT_STREAM_ERROR;
        }
    }
    
    public boolean isError() {
        try {
            long avail = ifs.available();
        } catch (IOException exc) {
            return true;
        }
        return false;
    }
    
    public boolean isEof() {
        try {
            long avail = ifs.available();
            if (avail > 0) return false;
        } catch (IOException exc) {
            return true;
        }
        return true;
    }
}
