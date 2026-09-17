import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';

export function activate(context: vscode.ExtensionContext) {
    // Compile command
    const compile = vscode.commands.registerCommand('jocky.compile', () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor || !editor.document.fileName.endsWith('.jocky')) {
            vscode.window.showErrorMessage('Open a .jocky file first');
            return;
        }

        const config = vscode.workspace.getConfiguration('jocky');
        const compiler: string = config.get('compilerPath', 'jocky-compile');
        const target: string = config.get('defaultTarget', 'linux');
        const input = editor.document.fileName;
        const output = input.replace(/\.jocky$/, '.ll');

        const term = vscode.window.createTerminal('JOCKY Compiler');
        term.show();
        term.sendText(
            `JOCKY_ALLOW_DEV_KEY=1 "${compiler}" compile --input "${input}" --output "${output}" --target ${target}`
        );
    });

    // New session command
    const newSession = vscode.commands.registerCommand('jocky.newSession', async () => {
        const template = await vscode.window.showQuickPick(
            ['triage', 'windows-persistence', 'linux-ebpf', 'pqc-vault'],
            { placeHolder: 'Select a session template' }
        );
        if (!template) return;

        const uri = await vscode.window.showSaveDialog({
            filters: { 'JOCKY Script': ['jocky'] },
            defaultUri: vscode.Uri.file(path.join(vscode.workspace.rootPath || '', `${template}.jocky`))
        });
        if (!uri) return;

        const config = vscode.workspace.getConfiguration('jocky');
        const compiler: string = config.get('compilerPath', 'jocky-compile');
        cp.exec(`"${compiler}" new ${template} --output "${uri.fsPath}"`, (err) => {
            if (err) {
                vscode.window.showErrorMessage(`jocky-compile error: ${err.message}`);
            } else {
                vscode.window.showTextDocument(uri);
            }
        });
    });

    context.subscriptions.push(compile, newSession);

    // Status bar item when a .jocky file is open
    const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBar.command = 'jocky.compile';
    statusBar.text = '$(play) JOCKY Compile';
    statusBar.tooltip = 'Compile this .jocky script to LLVM IR';
    context.subscriptions.push(statusBar);

    vscode.window.onDidChangeActiveTextEditor(editor => {
        if (editor?.document.fileName.endsWith('.jocky')) {
            statusBar.show();
        } else {
            statusBar.hide();
        }
    }, null, context.subscriptions);
}

export function deactivate() {}
