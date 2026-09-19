"""The host compiler and throwaway Git checkouts, for tests that build or describe something."""
import os
import subprocess


def compile_cpp(sources, output, includes=(), flags=()):
    """Compile ``sources`` into the executable ``output`` with the host C++17 compiler ($CXX, else c++)."""
    command = [os.environ.get("CXX", "c++"), "-std=c++17", *flags, *("-I" + str(path) for path in includes),
               *(str(source) for source in sources), "-o", str(output)]
    subprocess.run(command, check=True)
    return output


IDENTITY = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}


def git(repository, *arguments):
    """Run Git in ``repository`` under a fixed identity; returns stdout, stripped."""
    return subprocess.run(["git", "-C", str(repository), *arguments], check=True, capture_output=True, text=True,
                          env={**os.environ, **IDENTITY}).stdout.strip()


def repository(path, tag=None, commits_after_tag=0, head=None):
    """A throwaway checkout at ``path``: one empty commit, tagged ``tag`` when given, then ``commits_after_tag``
    more, like a post-release snapshot. ``head`` detaches HEAD at that id without needing the object, like a
    shallow, tagless CI checkout. Returns the id HEAD names."""
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q")
    git(path, "commit", "-q", "--allow-empty", "-m", "release" if tag else "init")
    if tag:
        git(path, "tag", "-a", tag, "-m", tag)
    for i in range(commits_after_tag):
        git(path, "commit", "-q", "--allow-empty", "-m", f"dev {i}")
    if head is not None:
        (path / ".git/HEAD").write_text(head + "\n")
        return head
    return git(path, "rev-parse", "HEAD")
