# Projeto: aigov, um scorecard de governança para código gerado por IA

## Objetivo
Construir uma CLI em Python que analisa um repositório e verifica se o código produzido com assistentes de IA generativa passa por controles básicos de governança. Ela gera um relatório HTML visual e um JSON para empresas e times de engenharia.

Mapeie os controles para as 4 funções do NIST AI RMF (Govern, Map, Measure, Manage) apenas como forma de organizar o relatório. Em nenhum lugar do código, do README ou do relatório diga que o resultado atesta "compliance" legal. Inclua um aviso explícito: é um scorecard heurístico, não é aconselhamento jurídico nem certificação.

## Restrições
- Python 3.9+, somente biblioteca padrão (zero dependências de runtime). Testes com `unittest`.
- Código, comentários, README e mensagens de CLI em inglês.
- A ferramenta é somente leitura. Nunca executa nem importa código do repositório analisado. Não segue symlinks. Ignora `.git`, `node_modules`, `vendor`, `venv`, `dist`, `build`.
- Limite de tamanho por arquivo (padrão 1 MB). Ignore arquivos binários.
- Segredos e dados pessoais encontrados NUNCA aparecem em claro no HTML, no JSON ou no console. Sempre mascarados (ex.: `sk-d… (40 characters, masked)`, `***.***.***-25`).
- Todo texto vindo do repositório é escapado com `html.escape` no HTML (nomes de arquivo, mensagens de commit, caminhos).

## Estrutura
```
aigov/{__init__,__main__,cli,models,policy,scanner,provenance,checks,engine,report}.py
tests/  examples/needs-remediation/  examples/remediated/
scripts/build_demo.py  .github/workflows/ci.yml  pyproject.toml  README.md  aigov.policy.json
```

## Sinais de proveniência (a ferramenta NÃO detecta autoria de IA; lê o que o time declara)
1. `.ai-provenance.json` na raiz:
```json
{
  "ai_systems": [{"provider": "anthropic", "purpose": "...", "owner": "...", "data_categories": ["..."]}],
  "files": [{"path": "src/x.py", "tool": "claude", "model": "...", "reviewed_by": "Nome", "reviewed_at": "2026-10-01"}]
}
```
Entradas inválidas são descartadas e reportadas como erro.

2. Marcadores no cabeçalho do arquivo (primeiras 40 linhas): `@ai-generated: <tool>` ou `@ai-assisted: <tool>`, com `@model:`, `@reviewed-by:` e `@reviewed-at:` opcionais. Só em arquivos de código. Remova terminadores de comentário (`*/`, `-->`).

3. Histórico git (via `git log`, com timeout de 30 s, `-c core.fsmonitor=false`, `GIT_TERMINAL_PROMPT=0`): um commit é "AI-assisted" se tiver um destes sinais:
   - `Co-authored-by` de um ator de IA (claude, copilot, cursor, codex, openai, chatgpt, gemini, devin, aider...);
   - rodapé "Generated with <ferramenta>";
   - trailer `AI-Assisted:` ou `Assisted-by:` com valor afirmativo;
   - autor de IA;
   - regex extra da política.

   A evidência de revisão é um trailer `Reviewed-by:` com um humano. Se o revisor for um ator de IA, não conta.

   Se não for um repositório git, o controle MAN-01 fica N/A.

Documente a limitação: a ausência de sinais NÃO prova que IA não foi usada.

## Os 13 controles (status: pass / warn / fail / na; peso entre parênteses)
GOVERN
- GOV-01 (3) Política de uso de IA: arquivo `AI_POLICY.md` ou `docs/ai-usage.md` etc. Checagem por palavras-chave: revisão humana, dados pessoais/sensíveis, ferramentas aprovadas, responsabilidade. Falta de arquivo = fail. Falta de tópico = warn.
- GOV-02 (2) CODEOWNERS com ao menos uma regra válida.
- GOV-03 (2) Template de PR que menciona IA e revisão humana.

MAP
- MAP-01 (3) Proveniência: todo arquivo declarado como gerado por IA tem revisor humano (um revisor que seja ferramenta de IA não conta). Entradas do manifesto apontando para arquivos inexistentes = warn. Se a política tiver `ai_usage: "none"` e houver sinais de IA = fail. Sem nenhum sinal = warn.
- MAP-02 (2) Inventário de LLMs: detecte provedores no código e em manifestos de dependência (openai, anthropic, google-gemini, mistral, cohere, groq, langchain, litellm, ollama, huggingface), ignorando linhas de comentário. Cada provedor detectado deve estar em `ai_systems`. Entradas sem provider/purpose/owner = warn.
- MAP-03 (3) Dados pessoais: CPF com validação de dígitos verificadores (formatado, ou 11 dígitos apenas se a linha contiver "cpf") e cartões validados por Luhn com prefixo plausível. Em pastas de teste/fixtures a severidade é medium. Fora delas, high.

MEASURE
- MEA-01 (3) Segredos: padrões específicos (AWS AKIA/ASIA, GitHub, Anthropic, OpenAI-style, Google, Slack, Stripe live, bloco de private key), mais atribuição genérica (`password|token|api_key = "..."`) com filtro de placeholder e entropia de Shannon >= 3.0. Arquivo `.env` presente e sem regra no `.gitignore` = high. `.env` ignorado pelo git não é escaneado. Específicos = critical.
- MEA-02 (2) Padrões arriscados (heurística, ignorar comentários e arquivos de teste): eval/exec, `shell=True`/`os.system`, pickle, `yaml.load` sem SafeLoader, `child_process.exec`, `innerHTML`, funções de execução do PHP, `unserialize`, TLS desativado (`verify=False`, `rejectUnauthorized:false`...) e SQL por concatenação. Severidade high se o arquivo for declarado como gerado por IA, senão medium.
- MEA-03 (2) Testes: razão arquivos de teste / arquivos de código >= `min_test_ratio`.

MANAGE
- MAN-01 (3) Evidência de revisão: % de commits AI-assisted com Reviewed-by humano >= `review_threshold` (padrão 80 %). Warn se >= metade do limite, senão fail.
- MAN-02 (2) CI configurado (GitHub Actions, GitLab, Jenkins, Azure, CircleCI, Bitbucket) e com passo de testes.
- MAN-03 (1) Dependências travadas: lockfile ao lado de package.json, composer.json, Pipfile, go.mod, Cargo.toml e Gemfile. Em requirements*.txt, versões com `==`. `pyproject.toml` com dependências precisa de lock (poetry/uv/pdm) ou de requirements pinado.
- MAN-04 (1) SECURITY.md (pass). Só runbook de incidente = warn.

Cada controle retorna: `id`, `title`, `function`, `weight`, `status`, `summary`, `why` (por que importa), `remediation`, `refs` e `findings` (mensagem, severidade info/low/medium/high/critical, arquivo, linha, evidência mascarada). Status a partir dos findings: high/critical = fail, medium/low = warn, nenhum = pass.

## Política (`aigov.policy.json`, chaves desconhecidas são erro)
`ai_usage` ("declared"|"none"), `min_score` (70), `block_on_critical` (true), `review_threshold` (0.8), `min_test_ratio` (0.1), `max_file_bytes`, `ignore` (globs), `disabled_controls`, `extra_ai_commit_patterns` (regex validados ao carregar). Controles desativados aparecem como N/A com "Disabled by policy".

## Supressões transparentes
`# aigov:ignore` na linha e `aigov:ignore-file` nas primeiras 40 linhas suprimem findings. Toda supressão usada DEVE aparecer listada no relatório e no JSON (arquivo e linha).

## Pontuação e veredito
Pontuação = soma(peso × pontos) / soma(pesos avaliados) × 100, onde pass = 1, warn = 0,5, fail = 0, e N/A é excluído. Calcule também a pontuação por função.
- Veredito: "Blocked" se houver finding critical. Senão "Aligned" (>= 85), "Partial" (>= 60), "Gaps".
- Saída: exit 0 / 1 / 2 (ok / gate falhou: score < limite ou critical com `block_on_critical` / erro de uso).

## CLI
`python -m aigov scan [PATH] [--policy FILE] [--html FILE] [--no-html] [--json FILE] [--fail-under N] [--quiet]`. Resumo no console com [PASS]/[WARN]/[FAIL]/[N/A], pontuação e veredito.

## Relatório HTML (autocontido: um arquivo, sem CDN nem fontes externas, JS opcional e mínimo)
Direção de design (decisões deliberadas, não o kit SaaS padrão):
- Tom de relatório de auditoria. Fundo azul-acinzentado claro `#F5F7F8`, tinta `#14202B`, acento `#2F5D8A`. Status: pass `#2E7D5B`, warn `#B7791F`, fail `#B3261E`, n/a `#8A97A3`. Modo escuro via `prefers-color-scheme`.
- Hero: o veredito como frase grande alinhada à esquerda (ex.: "Partial alignment: 3 controls need work before this ships"). Abaixo, uma faixa segmentada com 13 células, uma por controle, agrupadas por função e coloridas por status. Clicar numa célula leva ao controle. Essa faixa é o elemento memorável. O resto fica sóbrio.
- Status sempre com ícone + palavra, nunca só cor. Sem rótulos em caixa-alta, sem numeração decorativa, sem gradientes, sem cards idênticos.
- Seções: resumo por função, controles agrupados em `<details>` (resumo, por que importa, findings em tabela, remediação), tabela de proveniência, commits assistidos por IA, supressões, limitações e aviso de não-compliance. Fonte do sistema, mono para caminhos.
- Responsivo, foco visível, `prefers-reduced-motion`, CSS de impressão.

## Exemplos e demo
- `examples/needs-remediation`: app pequeno com um arquivo `@ai-generated` sem revisor, uma chave falsa hard-coded, um CPF sintético válido em fixture, `eval`, `verify=False`, import de LLM não inventariado, sem política, sem CODEOWNERS, sem testes.
- `examples/remediated`: o mesmo app corrigido, com política, CODEOWNERS, template de PR, manifesto completo, testes, CI, requirements pinado, SECURITY.md e segredo via variável de ambiente.
- `scripts/build_demo.py`: copia os exemplos para um diretório temporário, cria histórico git com commits que têm `Co-authored-by` de IA (sem Reviewed-by num e com Reviewed-by no outro), roda o scan e grava os relatórios em `docs/demo/`. Em testes e exemplos, monte strings que parecem segredo/CPF em tempo de execução ou use valores obviamente falsos, para o repositório poder passar no próprio scan.
- `aigov.policy.json` na raiz com `ignore: ["examples/*"]`. O projeto deve passar no scan de si mesmo.

## Testes (unittest)
- CPF válido/inválido, Luhn, mascaramento (o valor bruto nunca aparece na saída HTML/JSON), parsing de marcadores e trailers, git (repo temporário; pule se não houver git), cada controle em pass/warn/fail, política inválida, exit codes da CLI, escape de HTML (nome de arquivo com `<script>`), supressões listadas.

## README
O que é e o que NÃO é, quickstart, formato do manifesto, tabela de controles, política, uso em CI (exemplo de workflow que roda o scan e publica o HTML como artefato), limitações (heurísticas, falsos positivos/negativos, não detecta autoria), modelo de ameaça (somente leitura, nunca executa o repositório analisado).

## Como trabalhar
Faça em fases e rode `python -m unittest discover` ao fim de cada uma:
1. models, policy, scanner, provenance
2. checks e engine (pontuação)
3. CLI
4. relatório HTML
5. exemplos, demo e testes de integração
6. README e CI

Não adicione dependências. Em caso de ambiguidade, escolha a opção mais conservadora e registre no README. Ao final, mostre o relatório do exemplo `needs-remediation` e o do `remediated` lado a lado para validar visualmente.
