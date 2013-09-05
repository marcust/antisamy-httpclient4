package org.owasp.validator.css;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.ResponseHandler;

public class LimitedResponseHandler implements ResponseHandler<byte[]> {

    private final int sizeLimit;

    public LimitedResponseHandler( final int sizeLimit ) {
        this.sizeLimit = sizeLimit;
    }

    public byte[] handleResponse( final HttpResponse response ) throws ClientProtocolException, IOException {
        final StatusLine statusLine = response.getStatusLine();
        if (statusLine.getStatusCode() >= 300) {
            throw new HttpResponseException(statusLine.getStatusCode(),
                    statusLine.getReasonPhrase());
        }
        final HttpEntity entity = response.getEntity();
        final InputStream instream = entity.getContent();
        final long contentLength = entity.getContentLength();
        if ( contentLength > sizeLimit ) {
            throw new HttpContentTooLargeException();
        }

        final ByteArrayOutputStream outstream = new ByteArrayOutputStream();
        final byte[] buffer = new byte[1024];
        int len;
        int total = 0;
        while ((len = instream.read(buffer)) > 0 && total < this.sizeLimit ) {
            outstream.write(buffer, 0, len);
            total += len;
        }
        if ( total > this.sizeLimit ) {
            throw new HttpContentTooLargeException();
        }
        
        outstream.close();
        instream.close();
        
        return outstream.toByteArray();
    }

}
