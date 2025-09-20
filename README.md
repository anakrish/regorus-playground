# Regorus Playground

An interactive web-based playground for writing, testing, and debugging Rego policies using the Regorus engine powered by WebAssembly.

## 🚀 Features

- **Interactive Code Editor**: Monaco Editor with Rego syntax highlighting
- **Real-time Evaluation**: Execute Rego policies instantly in the browser
- **Split-panel Interface**: Separate editors for policy, input data, and static data
- **Built-in Examples**: Ready-to-use policy examples including:
  - Server security policies
  - Role-based access control (RBAC)
  - Data filtering policies
- **JSON Formatting**: Automatic formatting for input and output data
- **Error Handling**: Clear error messages and debugging information
- **Performance Metrics**: Execution time tracking
- **Responsive Design**: Works on desktop, tablet, and mobile devices

## 🎯 Quick Start

1. **Visit the Playground**: Navigate to the [live playground](https://your-username.github.io/regorus/playground/)
2. **Select an Example**: Choose from the dropdown menu to load a pre-built policy
3. **Edit the Policy**: Modify the Rego policy in the left panel
4. **Update Input/Data**: Provide JSON input and data as needed
5. **Evaluate**: Click the "Evaluate" button to see results
6. **Experiment**: Try different queries and policy modifications

## 📝 Example Usage

### Server Security Policy
```rego
package example

default allow := false

allow := true if {
    count(violation) == 0
}

violation[server.id] if {
    server := input.servers[_]
    server.protocols[_] == "http"
}
```

### Input Data
```json
{
    "servers": [
        {"id": "web", "protocols": ["https"]},
        {"id": "api", "protocols": ["http"]}
    ]
}
```

### Query
```
data.example.allow
```

## 🛠️ Development

### Local Development

1. **Build WASM Module**:
   ```bash
   cd bindings/wasm
   wasm-pack build --target web --out-dir pkg
   ```

2. **Copy WASM Files**:
   ```bash
   cp -r bindings/wasm/pkg docs/playground/
   ```

3. **Start Local Server**:
   ```bash
   cd docs
   python3 -m http.server 8080
   ```

4. **Open Playground**: Navigate to `http://localhost:8080/playground/`

### Project Structure

```
docs/
├── index.html              # Landing page
└── playground/
    ├── index.html          # Main playground interface
    ├── playground.css      # Styling
    ├── playground.js       # JavaScript logic and WASM integration
    └── pkg/               # WASM module files
        ├── regorusjs.js
        ├── regorusjs_bg.wasm
        └── ...
```

### Adding New Examples

To add a new example policy:

1. Edit `playground.js`
2. Add a new entry to the `examples` object:
   ```javascript
   'my-policy': {
       name: 'My Policy',
       policy: 'package my_policy\n\n...',
       input: '{"key": "value"}',
       data: '{}',
       query: 'data.my_policy'
   }
   ```
3. Add the option to the HTML select element

## 🚀 Deployment

The playground is automatically deployed to GitHub Pages using GitHub Actions:

1. **Push to main branch**: Triggers the build and deployment workflow
2. **WASM Build**: Compiles Regorus to WebAssembly
3. **Static Site Generation**: Prepares files for GitHub Pages
4. **Deployment**: Publishes to GitHub Pages

### Manual Deployment

1. Enable GitHub Pages in repository settings
2. Set source to "GitHub Actions"
3. Push changes to trigger deployment
4. Access playground at `https://username.github.io/repository/playground/`

## 🎨 Customization

### Themes
The playground uses Monaco Editor's VS Dark theme by default. To customize:

1. Modify the theme in `playground.js`:
   ```javascript
   monaco.editor.create(element, {
       theme: 'vs-light' // or custom theme
   });
   ```

### Styling
Edit `playground.css` to customize the appearance:

- Colors and fonts
- Layout and spacing  
- Responsive breakpoints
- Animation effects

### Examples
Modify the `examples` object in `playground.js` to:

- Add new policy examples
- Update existing policies
- Change default queries
- Customize input/data templates

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test locally
5. Submit a pull request

## 📄 License

This project is licensed under the same license as the main Regorus project.

## 🔗 Links

- [Regorus Repository](https://github.com/microsoft/regorus)
- [Rego Language Documentation](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Open Policy Agent](https://www.openpolicyagent.org/)