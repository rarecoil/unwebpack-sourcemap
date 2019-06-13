import * as React from "react";
import "./../assets/scss/App.scss";
import { FakeLibrary } from "../lib/LibraryCode";

// initialize a fakelibrary to use here.
const fakeLibraryInstance = new FakeLibrary();
let helloStr = fakeLibraryInstance.helloWorld();

export interface AppProps {
}

export default class App extends React.Component<AppProps, undefined> {
    render() {
        return (
            <div className="app">
                <h1>{helloStr}</h1>
                <p>
                This is a <code>React.Component</code> that has been Webpacked. Note that this
                source code, as well as the others, are published in the source map for this
                application.
                 </p>
                 <p>
                This is originally a TypeScript project that has been compiled to JS and then
                minified by <a href="">Webpack's TerserPlugin</a>. However, the source maps exist
                here, so we can extract them and recover the original build tree and source from
                these maps.
                 </p>
                 <p>
                To try it for yourself, run the source map script on this URI.
                 </p>
            </div>
        );
    }
}
