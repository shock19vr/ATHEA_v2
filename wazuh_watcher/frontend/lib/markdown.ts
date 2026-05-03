// Very lightweight markdown → HTML converter (no external deps)
export function renderMarkdown(text: string): string {
  return text
    // Code blocks (``` ... ```)
    .replace(/```[\w]*\n?([\s\S]*?)```/g, '<pre><code>$1</code></pre>')
    // Inline code
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    // Bold **text**
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    // Italic *text*
    .replace(/\*([^*]+)\*/g, '<em>$1</em>')
    // H3 ###
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    // H2 ##
    .replace(/^## (.+)$/gm, '<h2>$1</h2>')
    // H1 #
    .replace(/^# (.+)$/gm, '<h1>$1</h1>')
    // Bullet points - item
    .replace(/^[-•] (.+)$/gm, '<li>$1</li>')
    // Wrap consecutive <li> in <ul>
    .replace(/(<li>.*<\/li>\n?)+/g, (m) => `<ul>${m}</ul>`)
    // Line breaks → <br> (except inside pre/ul/h*)
    .replace(/\n(?!<\/?(ul|li|pre|h[123]|code))/g, '<br/>');
}
